use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use worker::Env;

use crate::handlers::{
    accounts, admin, attachments, auth_requests, ciphers, config, devices, domains, emergency_access,
    folders, identity, import, meta, org_admin, org_groups, org_policies, organizations, sends,
    sync, twofactor, twofactor_email, webauth, webauthn,
};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/prelogin/password",
            post(accounts::prelogin),
        )
        .route("/identity/accounts/register", post(accounts::register))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // For on-demand sync checks
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/password-hint", post(accounts::password_hint))
        .route("/api/tasks", get(accounts::get_tasks))
        .route("/api/accounts/profile", get(accounts::get_profile))
        .route("/api/accounts/profile", post(accounts::post_profile))
        .route("/api/accounts/profile", put(accounts::put_profile))
        .route("/api/accounts/avatar", put(accounts::put_avatar))
        // Delete account
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        // Set KDF
        .route("/api/accounts/kdf", post(accounts::post_kdf))
        // Change password
        .route("/api/accounts/password", post(accounts::post_password))
        // Log out all sessions via security stamp rotation
        .route("/api/accounts/security-stamp", post(accounts::post_sstamp))
        .route(
            "/api/accounts/key-management/user-key-id",
            post(accounts::post_user_key_id),
        )
        // Rotate encryption keys
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::post_rotatekey),
        )
        // Auth requests (login with device)
        .route(
            "/api/auth-requests",
            get(auth_requests::get_auth_requests).post(auth_requests::post_auth_request),
        )
        .route(
            "/api/auth-requests/pending",
            get(auth_requests::get_auth_requests_pending),
        )
        .route(
            "/api/auth-requests/{id}/response",
            get(auth_requests::get_auth_request_response),
        )
        .route(
            "/api/auth-requests/{id}",
            get(auth_requests::get_auth_request).put(auth_requests::put_auth_request),
        )
        // Ciphers CRUD
        .route("/api/ciphers", get(ciphers::list_ciphers))
        .route("/api/ciphers", post(ciphers::create_cipher_simple))
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        // Organization ciphers and admin aliases (phase 3.1)
        .route(
            "/api/ciphers/admin",
            post(ciphers::create_cipher).delete(ciphers::hard_delete_ciphers_bulk),
        )
        .route(
            "/api/ciphers/{id}/admin",
            get(ciphers::get_cipher)
                .put(ciphers::update_cipher)
                .post(ciphers::update_cipher)
                .delete(ciphers::hard_delete_cipher),
        )
        .route(
            "/api/ciphers/{id}/delete-admin",
            put(ciphers::soft_delete_cipher).post(ciphers::hard_delete_cipher),
        )
        .route(
            "/api/ciphers/{id}/restore-admin",
            put(ciphers::restore_cipher),
        )
        .route(
            "/api/ciphers/delete-admin",
            put(ciphers::soft_delete_ciphers_bulk).post(ciphers::hard_delete_ciphers_bulk),
        )
        .route(
            "/api/ciphers/restore-admin",
            put(ciphers::restore_ciphers_bulk),
        )
        .route(
            "/api/ciphers/{id}/share",
            put(ciphers::share_cipher).post(ciphers::share_cipher),
        )
        .route("/api/ciphers/share", put(ciphers::share_ciphers_bulk))
        .route(
            "/api/ciphers/{id}/collections",
            put(ciphers::update_cipher_collections).post(ciphers::update_cipher_collections),
        )
        .route(
            "/api/ciphers/{id}/collections-admin",
            put(ciphers::update_cipher_collections).post(ciphers::update_cipher_collections),
        )
        .route(
            "/api/ciphers/{id}/collections_v2",
            put(ciphers::update_cipher_collections_v2).post(ciphers::update_cipher_collections_v2),
        )
        .route(
            "/api/ciphers/organization-details",
            get(ciphers::get_org_details),
        )
        .route(
            "/api/ciphers/organization-details/assigned",
            get(ciphers::get_org_details_assigned),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete-admin",
            post(attachments::delete_attachment_post),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/admin",
            delete(attachments::delete_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment-admin",
            post(attachments::upload_attachment_legacy),
        )
        .route("/api/ciphers/import", post(import::import_data))
        .route("/api/ciphers/{id}", get(ciphers::get_cipher))
        .route(
            "/api/ciphers/{id}/details",
            get(ciphers::get_cipher_details),
        )
        // Attachments
        .route(
            "/api/ciphers/{id}/attachment/v2",
            post(attachments::create_attachment_v2),
        )
        // Note: Azure upload/download routes are intercepted in handlers::streaming (zero-copy)
        // PUT /api/ciphers/{id}/attachment/{attachment_id}/azure-upload
        // GET /api/ciphers/{id}/attachment/{attachment_id}/download?token=...
        .route(
            "/api/ciphers/{id}/attachment",
            post(attachments::upload_attachment_legacy),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            post(attachments::upload_attachment_v2_data),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            get(attachments::get_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            delete(attachments::delete_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete",
            post(attachments::delete_attachment_post),
        )
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        .route("/api/ciphers/{id}", post(ciphers::update_cipher))
        // Cipher soft delete (PUT sets deleted_at timestamp)
        .route("/api/ciphers/{id}/delete", put(ciphers::soft_delete_cipher))
        // Cipher hard delete (DELETE/POST permanently removes cipher)
        .route("/api/ciphers/{id}", delete(ciphers::hard_delete_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            post(ciphers::hard_delete_cipher),
        )
        // Partial update for folder/favorite
        .route(
            "/api/ciphers/{id}/partial",
            put(ciphers::update_cipher_partial),
        )
        .route(
            "/api/ciphers/{id}/partial",
            post(ciphers::update_cipher_partial),
        )
        // Cipher bulk soft delete
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers_bulk),
        )
        // Cipher bulk hard delete
        .route(
            "/api/ciphers/delete",
            post(ciphers::hard_delete_ciphers_bulk),
        )
        .route("/api/ciphers", delete(ciphers::hard_delete_ciphers_bulk))
        // Cipher restore (clears deleted_at)
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        // Cipher bulk restore
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers_bulk))
        // Cipher archive (sets archived_at)
        .route("/api/ciphers/{id}/archive", put(ciphers::archive_cipher))
        .route(
            "/api/ciphers/{id}/unarchive",
            put(ciphers::unarchive_cipher),
        )
        // Cipher bulk archive
        .route("/api/ciphers/archive", put(ciphers::archive_ciphers_bulk))
        .route(
            "/api/ciphers/unarchive",
            put(ciphers::unarchive_ciphers_bulk),
        )
        // Move ciphers to folder
        .route("/api/ciphers/move", post(ciphers::move_cipher_selected))
        .route("/api/ciphers/move", put(ciphers::move_cipher_selected))
        // Purge vault - delete all ciphers and folders (requires password verification)
        .route("/api/ciphers/purge", post(ciphers::purge_vault))
        // Folders CRUD
        .route("/api/folders", get(folders::list_folders))
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", get(folders::get_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/folders/{id}/delete", post(folders::delete_folder))
        // Sends
        .route("/api/sends", get(sends::list_sends))
        .route("/api/sends", post(sends::create_text_send))
        .route("/api/sends/file/v2", post(sends::create_file_send_v2))
        .route("/api/sends/file", post(sends::create_file_send_legacy))
        .route(
            "/api/sends/{send_id}/file/{file_id}",
            post(sends::upload_file_send_direct),
        )
        .route("/api/sends/{send_id}", get(sends::get_send))
        .route("/api/sends/{send_id}", put(sends::update_send))
        .route("/api/sends/{send_id}", delete(sends::delete_send))
        .route(
            "/api/sends/{send_id}/remove-password",
            put(sends::remove_password),
        )
        // Send anonymous access with a short-lived Bearer token.
        .route("/api/sends/access", post(sends::access_send_with_token))
        .route(
            "/api/sends/access/file/{file_id}",
            post(sends::access_file_send_with_token),
        )
        // Legacy Send anonymous access (body password behavior is retained).
        .route("/api/sends/access/{access_id}", post(sends::access_send))
        .route(
            "/api/sends/{send_id}/access/file/{file_id}",
            post(sends::access_file_send),
        )
        // Organizations (phase 3.1)
        .route(
            "/api/organizations",
            post(organizations::create_organization),
        )
        .route(
            "/api/organizations/{org_id}",
            get(organizations::get_organization)
                .put(organizations::put_organization)
                .post(organizations::put_organization)
                .delete(organizations::delete_organization),
        )
        .route(
            "/api/organizations/{org_id}/delete",
            post(organizations::delete_organization),
        )
        .route(
            "/api/organizations/{org_id}/leave",
            post(organizations::leave_organization),
        )
        .route(
            "/api/organizations/{org_id}/keys",
            get(organizations::get_org_keys).post(organizations::post_org_keys),
        )
        .route(
            "/api/organizations/{org_id}/public-key",
            get(organizations::get_org_public_key),
        )
        .route("/api/collections", get(organizations::get_user_collections))
        .route(
            "/api/organizations/{org_id}/collections",
            get(organizations::get_org_collections)
                .post(organizations::post_organization_collections)
                .delete(organizations::bulk_delete_organization_collections),
        )
        .route(
            "/api/organizations/{org_id}/collections/details",
            get(organizations::get_org_collections_details),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}",
            put(organizations::put_organization_collection)
                .post(organizations::put_organization_collection)
                .delete(organizations::delete_organization_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/delete",
            post(organizations::delete_organization_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/details",
            get(organizations::get_org_collection_detail),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/users",
            get(organizations::get_collection_users),
        )
        .route(
            "/api/organizations/{org_id}/users",
            get(organizations::get_members).delete(organizations::bulk_delete_members),
        )
        .route(
            "/api/organizations/{org_id}/users/invite",
            post(organizations::invite_members),
        )
        .route(
            "/api/organizations/{org_id}/users/reinvite",
            post(organizations::bulk_reinvite_members),
        )
        .route(
            "/api/organizations/{org_id}/users/confirm",
            post(organizations::bulk_confirm_members),
        )
        .route(
            "/api/organizations/{org_id}/users/public-keys",
            post(organizations::bulk_public_keys),
        )
        .route(
            "/api/organizations/{org_id}/users/mini-details",
            get(organizations::get_members_mini),
        )
        .route(
            "/api/organizations/{org_id}/users/revoke",
            put(organizations::bulk_revoke_members),
        )
        .route(
            "/api/organizations/{org_id}/users/restore",
            put(organizations::bulk_restore_members),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}",
            get(organizations::get_member)
                .put(organizations::edit_member)
                .post(organizations::edit_member)
                .delete(organizations::delete_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/delete",
            post(organizations::delete_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reinvite",
            post(organizations::reinvite_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/accept",
            post(organizations::accept_invite),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/confirm",
            post(organizations::confirm_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/revoke",
            put(organizations::revoke_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/restore",
            put(organizations::restore_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/restore/vnext",
            put(organizations::restore_member),
        )
        .route(
            "/api/organizations/{org_id}/billing/vnext/warnings",
            get(organizations::get_billing_warnings),
        )
        .route(
            "/api/organizations/{org_id}/billing/vnext/self-host/metadata",
            get(organizations::get_billing_metadata),
        )
        .route(
            "/api/organizations/{org_id}/auto-enroll-status",
            get(organizations::get_auto_enroll_status),
        )
        // Groups (phase 3.3)
        .route(
            "/api/organizations/{org_id}/groups",
            get(org_groups::get_groups)
                .post(org_groups::post_group)
                .delete(org_groups::bulk_delete_groups),
        )
        .route(
            "/api/organizations/{org_id}/groups/details",
            get(org_groups::get_groups_details),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}",
            get(org_groups::get_group)
                .put(org_groups::put_group)
                .post(org_groups::put_group)
                .delete(org_groups::delete_group),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/delete",
            post(org_groups::delete_group),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/details",
            get(org_groups::get_group_details),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/users",
            get(org_groups::get_group_members),
        )
        // Policies (phase 3.4)
        .route(
            "/api/organizations/{org_id}/policies",
            get(org_policies::list_policies),
        )
        .route(
            "/api/organizations/{org_id}/policies/token",
            get(org_policies::list_policies_token),
        )
        .route(
            "/api/organizations/{org_id}/policies/{pol_type}",
            get(org_policies::get_policy).put(org_policies::put_policy),
        )
        .route(
            "/api/organizations/{org_id}/policies/{pol_type}/vnext",
            put(org_policies::put_policy),
        )
        .route(
            "/api/organizations/{org_id}/collections/bulk-access",
            post(organizations::bulk_access_collections),
        )
        .route(
            "/api/ciphers/bulk-collections",
            post(organizations::bulk_cipher_collections),
        )
        .route(
            "/api/organizations/domain/sso/verified",
            post(organizations::sso_verified_domains),
        )
        .route(
            "/api/organizations/{org_id}/export",
            get(ciphers::export_organization),
        )
        .route(
            "/api/ciphers/import-organization",
            post(ciphers::import_organization),
        )
        // Account recovery, API key, events (phase 3.5)
        .route(
            "/api/organizations/{org_id}/users/{user_id}/reset-password-enrollment",
            put(org_admin::put_reset_password_enrollment),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password-details",
            get(org_admin::get_reset_password_details),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/recover-account",
            put(org_admin::recover_account),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password",
            put(org_admin::recover_account),
        )
        .route(
            "/api/organizations/{org_id}/api-key",
            post(org_admin::post_api_key),
        )
        .route(
            "/api/organizations/{org_id}/rotate-api-key",
            post(org_admin::rotate_api_key),
        )
        .route(
            "/api/organizations/{org_id}/events",
            get(org_admin::empty_events),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/events",
            get(org_admin::empty_events),
        )
        .route("/api/ciphers/{id}/events", get(org_admin::empty_events))
        .route(
            "/api/users/{user_id}/public-key",
            get(org_admin::get_user_public_key),
        )
        .route("/api/plans", get(organizations::get_plans))
        .route("/api/config", get(config::config))
        // Meta endpoints (mirrors a subset of vaultwarden core/mod.rs)
        .route("/api/alive", get(meta::alive))
        .route("/api/now", get(meta::now))
        .route("/api/version", get(meta::version))
        .route("/api/hibp/breach", get(meta::hibp_breach))
        // Settings (stubbed)
        .route("/api/settings/domains", get(domains::get_domains))
        .route("/api/settings/domains", post(domains::post_domains))
        .route("/api/settings/domains", put(domains::put_domains))
        // Emergency access
        .route(
            "/api/emergency-access/trusted",
            get(emergency_access::get_trusted_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(emergency_access::get_granted_access),
        )
        .route(
            "/api/emergency-access/invite",
            post(emergency_access::send_invite),
        )
        .route(
            "/api/emergency-access/{id}",
            get(emergency_access::get_emergency_access)
                .put(emergency_access::update_emergency_access)
                .post(emergency_access::update_emergency_access)
                .delete(emergency_access::delete_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/delete",
            post(emergency_access::delete_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/reinvite",
            post(emergency_access::resend_invite),
        )
        .route(
            "/api/emergency-access/{id}/accept",
            post(emergency_access::accept_invite),
        )
        .route(
            "/api/emergency-access/{id}/confirm",
            post(emergency_access::confirm_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/initiate",
            post(emergency_access::initiate_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/approve",
            post(emergency_access::approve_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/reject",
            post(emergency_access::reject_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/view",
            post(emergency_access::view_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/takeover",
            post(emergency_access::takeover_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/password",
            post(emergency_access::password_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/policies",
            get(emergency_access::policies_emergency_access),
        )
        // Devices (stub - device tracking not implemented, JWT-based auth)
        .route("/api/devices", get(devices::get_devices))
        .route("/api/devices/knowndevice", get(devices::get_known_device))
        .route(
            "/api/devices/identifier/{device_id}",
            get(devices::get_device),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            post(devices::post_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            put(devices::put_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            put(devices::put_clear_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            post(devices::post_clear_device_token),
        )
        // WebAuthn (stub - prevents 404 errors, passkeys not supported)
        .route("/api/webauthn", get(webauth::get_webauthn_credentials))
        // Two-factor authentication
        // Admin page
        .route("/admin", get(admin::admin_page).post(admin::login))
        .route("/admin/", get(admin::admin_page))
        .route("/admin/logout", get(admin::logout))
        .route("/admin/users", get(admin::users_json))
        .route("/admin/users/overview", get(admin::users_overview))
        .route(
            "/admin/users/{id}/invite/resend",
            post(admin::resend_invite),
        )
        .route("/admin/users/{id}/{action}", post(admin::post_user_action))
        .route("/admin/invite", post(admin::invite_user))
        .route(
            "/admin/organizations/overview",
            get(admin::organizations_overview),
        )
        .route(
            "/admin/organizations/{id}/delete",
            post(admin::delete_organization),
        )
        .route("/admin/diagnostics", get(admin::diagnostics))
        .route("/api/two-factor", get(twofactor::get_twofactor))
        .route(
            "/api/two-factor/get-authenticator",
            post(twofactor::get_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            post(twofactor::activate_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            put(twofactor::activate_authenticator_put),
        )
        .route(
            "/api/two-factor/authenticator",
            delete(twofactor::disable_authenticator),
        )
        .route(
            "/api/two-factor/disable",
            post(twofactor::disable_twofactor),
        )
        .route(
            "/api/two-factor/disable",
            put(twofactor::disable_twofactor_put),
        )
        .route("/api/two-factor/get-recover", post(twofactor::get_recover))
        .route(
            "/api/two-factor/get-email",
            post(twofactor_email::get_email),
        )
        .route(
            "/api/two-factor/send-email",
            post(twofactor_email::send_email),
        )
        .route(
            "/api/two-factor/email",
            put(twofactor_email::enable_email)
                .post(twofactor_email::enable_email)
                .delete(twofactor_email::disable_email),
        )
        .route(
            "/api/two-factor/send-email-login",
            post(twofactor_email::send_email_login),
        )
        .route(
            "/api/two-factor/get-webauthn",
            post(webauthn::get_webauthn),
        )
        .route(
            "/api/two-factor/get-webauthn-challenge",
            post(webauthn::get_webauthn_challenge),
        )
        .route(
            "/api/two-factor/webauthn",
            post(webauthn::activate_webauthn)
                .put(webauthn::activate_webauthn)
                .delete(webauthn::delete_webauthn),
        )
        .route(
            "/api/two-factor/webauthn/all",
            delete(webauthn::delete_all_webauthn),
        )
        .with_state(app_state)
}
