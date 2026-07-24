#[allow(
    clippy::too_many_lines,
    reason = "one sequential validator makes every cross-collection invariant visible at rehydration"
)]
fn group_policy_from_snapshot(
    snapshot: &GroupPolicySnapshot,
) -> Result<GroupPolicy, GroupPolicySnapshotError> {
    let members = collect_snapshot_set(&snapshot.members, "duplicate member")?;
    if !members.contains(&snapshot.owner_id) {
        return Err(invalid_snapshot("owner is not a member"));
    }
    let administrators = collect_snapshot_set(&snapshot.administrators, "duplicate administrator")?;
    if administrators.len() > MAX_ADMINS {
        return Err(invalid_snapshot("administrator limit exceeded"));
    }
    if administrators.contains(&snapshot.owner_id) {
        return Err(invalid_snapshot("owner is an administrator"));
    }
    if !administrators.is_subset(&members) {
        return Err(invalid_snapshot("administrator is not a member"));
    }

    let mut administrator_authorization_generations = BTreeMap::new();
    for (identity_id, generation) in &snapshot.administrator_authorization_generations {
        if *identity_id == snapshot.owner_id
            || administrator_authorization_generations
                .insert(*identity_id, *generation)
                .is_some()
        {
            return Err(invalid_snapshot(
                "duplicate or owner administrator generation",
            ));
        }
    }
    if administrators
        .iter()
        .any(|identity_id| !administrator_authorization_generations.contains_key(identity_id))
    {
        return Err(invalid_snapshot("administrator lacks authority generation"));
    }

    let mut invitations = BTreeMap::new();
    for invite in &snapshot.invitations {
        if invite.scope != snapshot.scope || invite.max_uses == 0 {
            return Err(invalid_snapshot("invalid invitation scope or use limit"));
        }
        let occupied_uses = invite
            .use_count
            .checked_add(invite.reserved_use_count)
            .ok_or_else(|| invalid_snapshot("invitation use count overflow"))?;
        if occupied_uses > invite.max_uses || invite.policy_revision > snapshot.revision {
            return Err(invalid_snapshot(
                "invalid invitation use or policy revision",
            ));
        }
        match invite.issuer_authority {
            InviteIssuerAuthority::Owner if invite.issuer_id != snapshot.owner_id => {
                return Err(invalid_snapshot("owner invitation has another issuer"));
            }
            InviteIssuerAuthority::Owner => {}
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => {
                if administrator_authorization_generations
                    .get(&invite.issuer_id)
                    .is_none_or(|current| *current < authorization_generation)
                {
                    return Err(invalid_snapshot("invitation authority generation mismatch"));
                }
            }
        }
        if invitations.insert(invite.invite_id, *invite).is_some() {
            return Err(invalid_snapshot("duplicate invitation"));
        }
    }

    let mut seen_join_ids = BTreeSet::new();
    let mut active_candidates = BTreeSet::new();
    let mut pending_joins = BTreeMap::new();
    for pending in &snapshot.pending_joins {
        if !seen_join_ids.insert(pending.request_id)
            || !invitations.contains_key(&pending.invite_id)
            || members.contains(&pending.candidate_id)
            || !active_candidates.insert(pending.candidate_id)
        {
            return Err(invalid_snapshot("invalid pending join"));
        }
        pending_joins.insert(pending.request_id, *pending);
    }

    let mut expected_reservations = BTreeMap::<InviteCapabilityId, u32>::new();
    let mut reserved_joins = BTreeMap::new();
    for reserved in &snapshot.reserved_joins {
        if !seen_join_ids.insert(reserved.request_id)
            || !invitations.contains_key(&reserved.invite_id)
            || members.contains(&reserved.candidate_id)
            || !active_candidates.insert(reserved.candidate_id)
            || reserved.policy_revision > snapshot.revision
        {
            return Err(invalid_snapshot("invalid membership reservation"));
        }
        match reserved.reserved_authority {
            InviteIssuerAuthority::Owner if reserved.reserved_by != snapshot.owner_id => {
                return Err(invalid_snapshot("owner reservation has another issuer"));
            }
            InviteIssuerAuthority::Owner => {}
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => {
                if administrator_authorization_generations
                    .get(&reserved.reserved_by)
                    .is_none_or(|current| *current < authorization_generation)
                {
                    return Err(invalid_snapshot(
                        "reservation authority generation mismatch",
                    ));
                }
            }
        }
        increment_snapshot_count(
            &mut expected_reservations,
            reserved.invite_id,
            "reservation count overflow",
        )?;
        reserved_joins.insert(reserved.request_id, *reserved);
    }

    let mut expected_uses = BTreeMap::<InviteCapabilityId, u32>::new();
    let mut approved_joins = BTreeMap::new();
    for approved in &snapshot.approved_joins {
        if !seen_join_ids.insert(approved.request_id)
            || !invitations.contains_key(&approved.invite_id)
            || !members.contains(&approved.candidate_id)
            || approved.policy_revision > snapshot.revision
        {
            return Err(invalid_snapshot("invalid approved join"));
        }
        increment_snapshot_count(
            &mut expected_uses,
            approved.invite_id,
            "approved use count overflow",
        )?;
        approved_joins.insert(approved.request_id, *approved);
    }

    for (invite_id, invite) in &invitations {
        if expected_reservations.get(invite_id).copied().unwrap_or(0) != invite.reserved_use_count
            || expected_uses.get(invite_id).copied().unwrap_or(0) != invite.use_count
        {
            return Err(invalid_snapshot(
                "invitation counters do not match join history",
            ));
        }
    }

    Ok(GroupPolicy {
        scope: snapshot.scope,
        owner_id: snapshot.owner_id,
        administrators,
        administrator_authorization_generations,
        members,
        invitations,
        pending_joins,
        reserved_joins,
        approved_joins,
        revision: snapshot.revision,
    })
}

fn collect_snapshot_set<T>(
    values: &[T],
    duplicate_reason: &'static str,
) -> Result<BTreeSet<T>, GroupPolicySnapshotError>
where
    T: Copy + Ord,
{
    let mut values_by_key = BTreeSet::new();
    for value in values {
        if !values_by_key.insert(*value) {
            return Err(invalid_snapshot(duplicate_reason));
        }
    }
    Ok(values_by_key)
}

fn increment_snapshot_count(
    counts: &mut BTreeMap<InviteCapabilityId, u32>,
    invite_id: InviteCapabilityId,
    overflow_reason: &'static str,
) -> Result<(), GroupPolicySnapshotError> {
    let count = counts.entry(invite_id).or_insert(0);
    *count = count
        .checked_add(1)
        .ok_or_else(|| invalid_snapshot(overflow_reason))?;
    Ok(())
}

const fn authority_persistence(authority: InviteIssuerAuthority) -> GroupAuthorityPersistence {
    match authority {
        InviteIssuerAuthority::Owner => GroupAuthorityPersistence::Owner,
        InviteIssuerAuthority::Admin {
            authorization_generation,
        } => GroupAuthorityPersistence::Admin {
            authorization_generation,
        },
    }
}

const fn authority_from_persistence(authority: GroupAuthorityPersistence) -> InviteIssuerAuthority {
    match authority {
        GroupAuthorityPersistence::Owner => InviteIssuerAuthority::Owner,
        GroupAuthorityPersistence::Admin {
            authorization_generation,
        } => InviteIssuerAuthority::Admin {
            authorization_generation,
        },
    }
}

const fn invalid_snapshot(reason: &'static str) -> GroupPolicySnapshotError {
    GroupPolicySnapshotError::InvalidSnapshot(reason)
}
