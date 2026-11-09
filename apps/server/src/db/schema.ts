import { sql } from 'drizzle-orm';
import {
  check,
  customType,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

const bytea = customType<{ data: Uint8Array; driverData: Buffer }>({
  dataType: () => 'bytea',
  toDriver: (v) => Buffer.from(v),
  fromDriver: (v) => new Uint8Array(v),
});

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    // Normalised (trim + lowercase) by the API; the CHECK below enforces it in the database.
    email: text('email').notNull().unique(),
    role: text('role', { enum: ['admin', 'user'] })
      .notNull()
      .default('user'),
    // OPAQUE registration record (opaque to the server, no password material).
    opaqueRecord: text('opaque_record').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    check('users_role_check', sql`${t.role} in ('admin', 'user')`),
    check(
      'users_email_check',
      sql`${t.email} = lower(btrim(${t.email})) and length(${t.email}) between 3 and 254`,
    ),
  ],
);

// The server only stores these blobs. Wrapping and unwrapping happen on the client.
export const wrappedUmk = pgTable(
  'wrapped_umk',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    kind: text('kind', { enum: ['password', 'recovery'] }).notNull(),
    keyId: bytea('key_id').notNull(),
    blob: bytea('blob').notNull(),
    // Format version of the blob, so a later KDF or cipher change does not have to guess.
    version: smallint('version').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.userId, t.kind] }),
    check('wrapped_umk_kind_check', sql`${t.kind} in ('password', 'recovery')`),
    check('wrapped_umk_blob_size_check', sql`octet_length(${t.blob}) between 1 and 512`),
    check('wrapped_umk_key_id_size_check', sql`octet_length(${t.keyId}) between 1 and 64`),
  ],
);
