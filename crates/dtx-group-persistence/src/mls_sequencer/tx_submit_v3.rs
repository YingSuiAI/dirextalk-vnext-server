async fn submit_v3_in_transaction<FS>(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    now_ms: i64,
    sequencer_signing_key: SigningPublicKey,
    sign_receipt: FS,
) -> Result<MlsCommitExecution, GroupPersistenceError>
where
    FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
{
    let execution = submit_in_transaction(
        connection,
        tenant_id,
        command,
        now_ms,
        sequencer_signing_key,
        |_| Ok(()),
        |_| Ok(()),
        sign_receipt,
    )
    .await?;
    let MlsCommitAuthorization::ApprovedIdentityJoinV3 {
        membership_command_id,
        ..
    } = command.authorization
    else {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    };
    resolve_mls_commit_in_transaction(
        connection,
        tenant_id,
        command.scope,
        membership_command_id,
        execution.receipt.receipt_digest,
        now_ms,
    )
    .await?;
    Ok(execution)
}
