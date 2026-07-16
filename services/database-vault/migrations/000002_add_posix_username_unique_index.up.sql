-- ST-F-11: Storage-Service's AuthorizedKeysCommand looks a user up by
-- posix_username (see storage.GetSSHPublicKeyByPosixUsername), not by
-- email_hash. posix_username had no index of its own beyond the table's
-- physical storage, and no uniqueness constraint distinct from the random
-- generation in internal/posix.GenerateUsername (DV-F-09) actually
-- guaranteeing collisions can't happen. A unique index both makes this
-- lookup efficient and turns a generator collision (36^6 possible values,
-- vanishingly unlikely but not impossible) into a hard database error at
-- insert time instead of two SSH accounts silently sharing one username.
CREATE UNIQUE INDEX idx_users_posix_username ON users (posix_username);
