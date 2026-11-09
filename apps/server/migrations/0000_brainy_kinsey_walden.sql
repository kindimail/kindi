CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"role" text DEFAULT 'user' NOT NULL,
	"opaque_record" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email"),
	CONSTRAINT "users_role_check" CHECK ("users"."role" in ('admin', 'user')),
	CONSTRAINT "users_email_check" CHECK ("users"."email" = lower(btrim("users"."email")) and length("users"."email") between 3 and 254)
);
--> statement-breakpoint
CREATE TABLE "wrapped_umk" (
	"user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"key_id" "bytea" NOT NULL,
	"blob" "bytea" NOT NULL,
	"version" smallint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "wrapped_umk_user_id_kind_pk" PRIMARY KEY("user_id","kind"),
	CONSTRAINT "wrapped_umk_kind_check" CHECK ("wrapped_umk"."kind" in ('password', 'recovery')),
	CONSTRAINT "wrapped_umk_blob_size_check" CHECK (octet_length("wrapped_umk"."blob") between 1 and 512),
	CONSTRAINT "wrapped_umk_key_id_size_check" CHECK (octet_length("wrapped_umk"."key_id") between 1 and 64)
);
--> statement-breakpoint
ALTER TABLE "wrapped_umk" ADD CONSTRAINT "wrapped_umk_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;