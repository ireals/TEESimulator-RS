package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.GeneratedKeyPersistence
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private val stubBinderClass = IKeystoreService.Stub::class.java

    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val GRANT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "grant")
    private val UNGRANT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "ungrant")
    private val LIST_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION =
        if (Build.VERSION.SDK_INT >= 34)
            InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched")
        else null
    private val GET_NUMBER_OF_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getNumberOfEntries")

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    private const val RESPONSE_PERMISSION_DENIED = 6
    private const val RESPONSE_KEY_NOT_FOUND = 7
    private const val KEY_PERMISSION_GET_INFO = 0x4
    private const val KEY_PERMISSION_USE = 0x100

    private data class GrantMapping(
        val ownerKeyId: KeyIdentifier,
        val granteeUid: Int,
        val accessVector: Int,
    )

    private data class PendingGrant(
        val ownerKeyId: KeyIdentifier,
        val granteeUid: Int,
        val accessVector: Int,
    )

    private val deletedSoftwareKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
    private val userUpdatedKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
    private val pendingGrants = ConcurrentHashMap<Long, PendingGrant>()
    private val grantsByNspace = ConcurrentHashMap<Long, GrantMapping>()

    fun forgetDeletedKey(keyId: KeyIdentifier) {
        if (deletedSoftwareKeys.remove(keyId)) {
            SystemLogger.debug("Cleared deletion marker for ${keyId.alias}")
        }
    }

    fun forgetGrantsForKey(keyId: KeyIdentifier) {
        val grantIds = grantsByNspace
            .filterValues { it.ownerKeyId == keyId }
            .keys
        grantIds.forEach { grantsByNspace.remove(it) }
        if (grantIds.isNotEmpty()) {
            SystemLogger.debug("Cleared ${grantIds.size} grant mappings for ${keyId.alias}")
        }
    }

    fun resolveGrantOwner(nspace: Long?): KeyIdentifier? {
        if (nspace == null || nspace == 0L) return null
        return grantsByNspace[nspace]?.ownerKeyId
    }

    fun resolveGrantOwnerForUse(nspace: Long?, callingUid: Int): KeyIdentifier? {
        val grant = resolveGrant(nspace) ?: return null
        if (!grant.allowsCaller(callingUid) || !grant.allowsUse()) return null
        return grant.ownerKeyId
    }

    private fun resolveGrant(nspace: Long?): GrantMapping? {
        if (nspace == null || nspace == 0L) return null
        return grantsByNspace[nspace]
    }

    private fun GrantMapping.allowsCaller(uid: Int): Boolean = granteeUid == uid

    private fun GrantMapping.allowsGetInfo(): Boolean =
        accessVector and KEY_PERMISSION_GET_INFO != 0

    private fun GrantMapping.allowsUse(): Boolean =
        accessVector and KEY_PERMISSION_USE != 0

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        listOfNotNull(
                GET_KEY_ENTRY_TRANSACTION,
                DELETE_KEY_TRANSACTION,
                UPDATE_SUBCOMPONENT_TRANSACTION,
                GRANT_TRANSACTION,
                UNGRANT_TRANSACTION,
                LIST_ENTRIES_TRANSACTION,
                LIST_ENTRIES_BATCHED_TRANSACTION,
                GET_NUMBER_OF_ENTRIES_TRANSACTION,
            )
            .toIntArray()
    }

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(
                        backdoor,
                        tee.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(
                        backdoor,
                        strongbox.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return if (ConfigurationManager.shouldSkipUid(callingUid))
                TransactionResult.ContinueAndSkipPost
            else TransactionResult.Continue
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)

            val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
            val isGMS = packages.contains("com.google.android.gms")

            if (isGMS || ConfigurationManager.shouldSkipUid(callingUid)) {
                return TransactionResult.ContinueAndSkipPost
            }

            return runCatching {
                    val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                    if (ListEntriesHandler.cacheParameters(txId, data, isBatchMode)) {
                        TransactionResult.Continue
                    } else {
                        TransactionResult.ContinueAndSkipPost
                    }
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to parse parameters for ${transactionNames[code]!!}",
                        it,
                    )
                    TransactionResult.ContinueAndSkipPost
                }
        } else if (
            code == GET_KEY_ENTRY_TRANSACTION ||
                code == DELETE_KEY_TRANSACTION ||
                code == UPDATE_SUBCOMPONENT_TRANSACTION ||
                code == GRANT_TRANSACTION ||
                code == UNGRANT_TRANSACTION
        ) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            val skipUid = ConfigurationManager.shouldSkipUid(callingUid)

            if (code == UPDATE_SUBCOMPONENT_TRANSACTION) {
                if (skipUid) return TransactionResult.ContinueAndSkipPost
                return handleUpdateSubcomponent(callingUid, data)
            }

            if (code == GRANT_TRANSACTION) {
                if (skipUid) return TransactionResult.ContinueAndSkipPost
                return handleGrant(txId, callingUid, data)
            }

            if (code == UNGRANT_TRANSACTION) {
                if (skipUid) return TransactionResult.ContinueAndSkipPost
                return handleUngrant(callingUid, data)
            }

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost

            if (code == DELETE_KEY_TRANSACTION) {
                if (skipUid)
                    return TransactionResult.ContinueAndSkipPost

                val keyId =
                    if (descriptor.alias != null) {
                        KeyIdentifier(callingUid, descriptor.alias)
                    } else if (descriptor.domain == Domain.KEY_ID) {
                        KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                            callingUid, descriptor.nspace
                        )?.let { info ->
                            KeyMintSecurityLevelInterceptor.generatedKeys.entries
                                .find { it.value.nspace == info.nspace && it.key.uid == callingUid }
                                ?.key
                        }
                    } else null

                if (keyId != null) {
                    val isSoftwareKey =
                        KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(keyId)
                    KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                    forgetGrantsForKey(keyId)
                    if (isSoftwareKey) {
                        deletedSoftwareKeys.add(keyId)
                        SystemLogger.info(
                            "[TX_ID: $txId] Deleted cached keypair ${keyId.alias}, replying with empty response."
                        )
                        return InterceptorUtils.createSuccessReply(writeResultCode = false)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }

            if (descriptor.domain == Domain.GRANT) {
                val grant = resolveGrant(descriptor.nspace)
                if (grant != null && !grant.allowsCaller(callingUid)) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Rejecting GRANT nspace=${descriptor.nspace} " +
                            "for non-grantee uid=$callingUid expected=${grant.granteeUid}"
                    )
                    return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                }
                if (grant != null && !grant.allowsGetInfo()) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Rejecting GRANT nspace=${descriptor.nspace} " +
                            "for uid=$callingUid without GET_INFO access"
                    )
                    return InterceptorUtils.createErrorReply(RESPONSE_PERMISSION_DENIED)
                }
                val response = grant?.ownerKeyId?.let {
                    KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(it)
                }
                if (response != null) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Resolved GRANT nspace=${descriptor.nspace} to ${grant.ownerKeyId}"
                    )
                    return InterceptorUtils.createTypedObjectReply(
                        responseForDescriptor(response, descriptor)
                    )
                }
                SystemLogger.debug(
                    "[TX_ID: $txId] No cached response for GRANT nspace=${descriptor.nspace}; forwarding"
                )
                return TransactionResult.ContinueAndSkipPost
            }

            if (skipUid)
                return TransactionResult.ContinueAndSkipPost

            if (descriptor.alias == null) {
                if (descriptor.domain == Domain.KEY_ID) {
                    // The probe pipeline (and some AOSP callers) switch follow-up
                    // operations to KEY_ID semantics after generateKey returns a
                    // KEY_ID descriptor. Without this branch, our software keys
                    // are invisible to KEY_ID-based getKeyEntry calls and the
                    // request falls through to the real keystore2 daemon, which
                    // legitimately responds with KEY_NOT_FOUND. Duck Detector's
                    // TimingSideChannelProbe captures that exception during its
                    // warmup phase and surfaces it as
                    // "Captured private binder exception during timing skip".
                    // Resolving by KEY_ID and returning the cached response keeps
                    // the call on the happy path, eliminating the warmup signal.
                    val info = KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                        callingUid, descriptor.nspace
                    )
                    if (info?.response != null) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Found generated response via KEY_ID nspace=${descriptor.nspace}"
                        )
                        return InterceptorUtils.createTypedObjectReply(info.response)
                    }
                    val teeResp = KeyMintSecurityLevelInterceptor.findTeeResponseByKeyId(
                        callingUid, descriptor.nspace
                    )
                    if (teeResp != null) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Found TEE response via KEY_ID nspace=${descriptor.nspace}"
                        )
                        return InterceptorUtils.createTypedObjectReply(teeResp)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
            if (response == null) {
                if (deletedSoftwareKeys.remove(keyId)) {
                    SystemLogger.info("[TX_ID: $txId] Returning KEY_NOT_FOUND for deleted key ${descriptor.alias}")
                    return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                }
                return TransactionResult.Continue
            }

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(it.keyParameter)
            }
            return InterceptorUtils.createTypedObjectReply(response)
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                true,
            )
        }

        // Let most calls go through to the real service.
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (target != keystoreService || reply == null) return TransactionResult.SkipTransaction
        if (InterceptorUtils.hasException(reply)) {
            if (code == GRANT_TRANSACTION) pendingGrants.remove(txId)
            val normalized = InterceptorUtils.normalizeServiceSpecificReply(reply)
            return if (normalized != null) TransactionResult.OverrideReply(normalized)
            else TransactionResult.SkipTransaction
        }

        if (code == GRANT_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            return runCatching {
                    val pending = pendingGrants.remove(txId)
                        ?: return TransactionResult.SkipTransaction
                    val grantDescriptor = reply.readTypedObject(KeyDescriptor.CREATOR)
                        ?: return TransactionResult.SkipTransaction
                    if (grantDescriptor.domain == Domain.GRANT && grantDescriptor.nspace != 0L) {
                        grantsByNspace[grantDescriptor.nspace] = GrantMapping(
                            ownerKeyId = pending.ownerKeyId,
                            granteeUid = pending.granteeUid,
                            accessVector = pending.accessVector,
                        )
                        SystemLogger.info(
                            "[TX_ID: $txId] Recorded grant nspace=${grantDescriptor.nspace} " +
                                "for ${pending.ownerKeyId} -> uid=${pending.granteeUid} " +
                                "accessVector=0x${pending.accessVector.toString(16)}"
                        )
                    }
                    TransactionResult.SkipTransaction
                }
                .getOrElse {
                    pendingGrants.remove(txId)
                    SystemLogger.error("[TX_ID: $txId] Failed to record grant mapping.", it)
                    TransactionResult.SkipTransaction
                }
        }

        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            return runCatching {
                    val hardwareCount = reply.readInt()
                    val softwareCount =
                        KeyMintSecurityLevelInterceptor.generatedKeys.keys.count {
                            it.uid == callingUid
                        }
                    val totalCount = hardwareCount + softwareCount
                    val parcel = Parcel.obtain().apply {
                        writeNoException()
                        writeInt(totalCount)
                    }
                    TransactionResult.OverrideReply(parcel)
                }
                .getOrElse {
                    SystemLogger.error("[TX_ID: $txId] Failed to modify getNumberOfEntries.", it)
                    TransactionResult.SkipTransaction
                }
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            return runCatching {
                    val updatedKeyDescriptors =
                        ListEntriesHandler.injectGeneratedKeys(txId, callingUid, reply)
                    InterceptorUtils.createTypedArrayReply(updatedKeyDescriptors)
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to update the result of ${transactionNames[code]!!}.",
                        it,
                    )
                    TransactionResult.SkipTransaction
                }
        } else if (code == GET_KEY_ENTRY_TRANSACTION) {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            logTransaction(
                txId,
                "post-${transactionNames[code]!!} ${keyDescriptor.alias}",
                callingUid,
                callingPid,
            )

            if (!ConfigurationManager.shouldPatch(callingUid))
                return TransactionResult.SkipTransaction

            runCatching {
                    val response = reply.readTypedObject(KeyEntryResponse.CREATOR)!!
                    val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                    if (userUpdatedKeys.remove(keyId)) {
                        SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: userUpdated=true, skipping patch" }
                        SystemLogger.debug("[TX_ID: $txId] Skipping cert patch for user-updated key $keyId.")
                        return TransactionResult.SkipTransaction
                    }

                    val authorizations = response.metadata.authorizations
                    val parsedParameters =
                        KeyMintAttestation(
                            authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
                        )

                    SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: isImport=${parsedParameters.isImportKey()} origin=${parsedParameters.origin} inImportedKeys=${KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)} hasPatchedChain=${KeyMintSecurityLevelInterceptor.getPatchedChain(keyId) != null} isAttestKey=${parsedParameters.isAttestKey()}" }

                    if (parsedParameters.isImportKey()) {
                        SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: imported key, skip patching" }
                        SystemLogger.info("[TX_ID: $txId] Skip patching for imported key $keyId.")
                        return TransactionResult.SkipTransaction
                    }

                    if (KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)) {
                        SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: in importedKeys set, skip" }
                        SystemLogger.debug("[TX_ID: $txId] Skipping attest-key override for imported key $keyId")
                        return TransactionResult.SkipTransaction
                    }

                    if (parsedParameters.isAttestKey()) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] Found hardware attest key ${keyId.alias} in the reply."
                        )
                        val keyData =
                            CertificateGenerator.generateAttestedKeyPair(
                                callingUid,
                                keyId.alias,
                                null,
                                parsedParameters,
                                response.metadata.keySecurityLevel,
                            ) ?: throw Exception("Failed to create overriding attest key pair.")

                        CertificateHelper.updateCertificateChain(
                                response.metadata,
                                keyData.second.toTypedArray(),
                            )
                            .getOrThrow()
                        response.metadata.authorizations =
                            InterceptorUtils.patchAuthorizations(
                                response.metadata.authorizations,
                                callingUid,
                            )

                        val newNspace = SecureRandom().nextLong()
                        response.metadata.key?.let { it.nspace = newNspace }
                        KeyMintSecurityLevelInterceptor.generatedKeys[keyId] =
                            KeyMintSecurityLevelInterceptor.GeneratedKeyInfo(
                                keyData.first,
                                null,
                                newNspace,
                                response,
                                parsedParameters,
                            )
                        KeyMintSecurityLevelInterceptor.attestationKeys.add(keyId)

                        // Snapshot metadata bytes for the same reason as the
                        // primary doSoftwareKeyGen path — loss-less restore
                        // after reboot.
                        val metadataBytesForPersist = response.metadata?.let { md ->
                            runCatching {
                                val parcel = android.os.Parcel.obtain()
                                try {
                                    md.writeToParcel(parcel, 0)
                                    parcel.marshall()
                                } finally {
                                    parcel.recycle()
                                }
                            }.getOrNull()
                        }
                        GeneratedKeyPersistence.save(
                            keyId = keyId,
                            keyPair = keyData.first,
                            secretKey = null,
                            nspace = newNspace,
                            securityLevel = response.metadata.keySecurityLevel,
                            certChain = keyData.second,
                            algorithm = parsedParameters.algorithm,
                            keySize = parsedParameters.keySize,
                            ecCurve = parsedParameters.ecCurve ?: 0,
                            purposes = parsedParameters.purpose,
                            digests = parsedParameters.digest,
                            isAttestationKey = true,
                            metadataBytes = metadataBytesForPersist,
                        )

                        return InterceptorUtils.createTypedObjectReply(response)
                    }

                    val originalChain = CertificateHelper.getCertificateChain(response)

                    if (originalChain == null || originalChain.size < 2) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Skip patching short certificate chain of length ${originalChain?.size}."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    val cachedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)

                    val finalChain: Array<Certificate>
                    if (cachedChain != null) {
                        SystemLogger.debug(
                            "[TX_ID: $txId] Using cached patched certificate chain for $keyId."
                        )
                        finalChain = cachedChain
                    } else {
                        SystemLogger.info(
                            "[TX_ID: $txId] No cached chain for $keyId. Performing live patch as a fallback."
                        )
                        finalChain =
                            AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                        KeyMintSecurityLevelInterceptor.patchedChains[keyId] = finalChain
                    }

                    CertificateHelper.updateCertificateChain(response.metadata, finalChain)
                        .getOrThrow()
                    response.metadata.authorizations =
                        InterceptorUtils.patchAuthorizations(
                            response.metadata.authorizations,
                            callingUid,
                        )

                    return InterceptorUtils.createTypedObjectReply(response)
                }
                .onFailure {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to modify hardware KeyEntryResponse.",
                        it,
                    )
                    return TransactionResult.SkipTransaction
                }
        }
        return TransactionResult.SkipTransaction
    }

    private fun handleGrant(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost
                val granteeUid = data.readInt()
                val accessVector = data.readInt()
                val ownerKeyId = resolveKeyIdentifier(callingUid, descriptor)

                if (ownerKeyId != null) {
                    pendingGrants[txId] = PendingGrant(ownerKeyId, granteeUid, accessVector)
                    SystemLogger.debug(
                        "[TX_ID: $txId] Tracking grant request for ${ownerKeyId} -> " +
                            "uid=$granteeUid accessVector=0x${accessVector.toString(16)}"
                    )
                }

                TransactionResult.Continue
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed to parse grant request.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleUngrant(callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost

                if (descriptor.domain == Domain.GRANT && descriptor.nspace != 0L) {
                    grantsByNspace.remove(descriptor.nspace)
                } else {
                    resolveKeyIdentifier(callingUid, descriptor)?.let { forgetGrantsForKey(it) }
                }

                TransactionResult.ContinueAndSkipPost
            }
            .getOrElse {
                SystemLogger.error("Failed to parse ungrant request.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun resolveKeyIdentifier(
        callingUid: Int,
        descriptor: KeyDescriptor,
    ): KeyIdentifier? {
        return when (descriptor.domain) {
            Domain.APP -> descriptor.alias?.let { KeyIdentifier(callingUid, it) }
            Domain.KEY_ID ->
                KeyMintSecurityLevelInterceptor.findKeyIdentifierByKeyId(
                    callingUid,
                    descriptor.nspace,
                )
            Domain.GRANT -> resolveGrantOwnerForUse(descriptor.nspace, callingUid)
            else -> null
        }
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            ?: return TransactionResult.ContinueAndSkipPost

        val keyId = resolveKeyIdentifier(callingUid, descriptor)
        val generatedKeyInfo = keyId?.let {
            KeyMintSecurityLevelInterceptor.generatedKeys[it]
        }

        val publicCert = data.createByteArray()
        val certificateChain = data.createByteArray()

        val cachedTeeResponse = keyId?.let {
            KeyMintSecurityLevelInterceptor.teeResponses[it]
        }

        if (generatedKeyInfo == null) {
            if (keyId != null && cachedTeeResponse != null) {
                SystemLogger.info("Updating cached TEE sub-component with key[${descriptor.nspace}]")
                cachedTeeResponse.metadata?.let { metadata ->
                    metadata.certificate = publicCert
                    metadata.certificateChain = certificateChain
                }
                KeyMintSecurityLevelInterceptor.patchedChains.remove(keyId)
                return TransactionResult.ContinueAndSkipPost
            }

            descriptor.alias?.let {
                val kid = KeyIdentifier(callingUid, it)
                userUpdatedKeys.add(kid)
                SystemLogger.trace { "[TRACE] updateSubcomponent $kid: not generated key, added to userUpdatedKeys" }
            }
            return TransactionResult.ContinueAndSkipPost
        }

        SystemLogger.info("Updating sub-component with key[${generatedKeyInfo.nspace}]")
        val metadata = generatedKeyInfo.response.metadata

        metadata.certificate = publicCert
        metadata.certificateChain = certificateChain

        GeneratedKeyPersistence.rePersistIfNeeded(callingUid, generatedKeyInfo)

        SystemLogger.verbose(
            "Key updated with sizes: [publicCert, certificateChain] = [${publicCert?.size}, ${certificateChain?.size}]"
        )

        return InterceptorUtils.createSuccessReply(writeResultCode = false)
    }

    private fun responseForDescriptor(
        response: KeyEntryResponse,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        return KeyEntryResponse().apply {
            metadata = cloneMetadata(response.metadata)?.also { metadata ->
                metadata.key = KeyDescriptor().apply {
                    domain = descriptor.domain
                    nspace = descriptor.nspace
                    alias = descriptor.alias
                    blob = descriptor.blob?.clone()
                }
            }
            iSecurityLevel = response.iSecurityLevel
        }
    }

    private fun cloneMetadata(metadata: KeyMetadata?): KeyMetadata? {
        metadata ?: return null
        val parcel = Parcel.obtain()
        return try {
            metadata.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            KeyMetadata.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }
}
