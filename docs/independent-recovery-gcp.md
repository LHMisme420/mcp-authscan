# Google Cloud operator runbook

This runbook deploys the opt-in recovery job in the owner-controlled GCP project.
It does not run from the Replit web app. The owner-reported destination is project
`vata-511710`, bucket `bucket-quickstart_vata-511710`, location `US`
(multi-region), Standard class. The job refuses to export if the bucket is not
US multi-region Standard, private, or has an automatic delete rule / locked
retention policy.

Never paste a database URL, key, token, or service-account credential into chat,
Git, a shell command, or the image build. Enter the source URL and key directly
into Google Secret Manager. The job uses its attached service account; do not
create or download a service-account key.

## Build the job image

Use Google Cloud Shell while signed into the owner-controlled GCP account. Confirm
the production PostgreSQL major version first. The `pg_dump` client must be that
major version or a supported newer one; the program checks this before exporting.

```sh
PROJECT_ID='vata-511710'
RUN_REGION='us-east4'
PG_MAJOR='replace-with-source-major'
IMAGE="${RUN_REGION}-docker.pkg.dev/${PROJECT_ID}/recovery-images/recovery-job:$(date -u +%Y%m%d%H%M)"

gcloud services enable \
  artifactregistry.googleapis.com cloudbuild.googleapis.com \
  run.googleapis.com cloudscheduler.googleapis.com secretmanager.googleapis.com \
  --project="${PROJECT_ID}"

gcloud artifacts repositories create recovery-images \
  --repository-format=docker --location="${RUN_REGION}" --project="${PROJECT_ID}"

gcloud builds submit \
  --project="${PROJECT_ID}" \
  --config=cloudbuild.recovery.yaml \
  --substitutions="_PG_MAJOR=${PG_MAJOR},_IMAGE=${IMAGE}" .
```

If the Artifact Registry repository already exists, skip its create command.
Replace `PG_MAJOR` with the actual source major version before building. Cloud
Build uses `.gcloudignore`; local environment files, keys, archives, database
files, and build output are excluded.

## Create secrets and the runtime identity

1. In Secret Manager, create `vata-recovery-source` containing the explicitly
   approved production PostgreSQL URL. Do not use the app's implicit
   `DATABASE_URL`.
2. Generate a fresh 32-byte random key on a trusted operator machine. Store the
   base64 representation as the `vata-recovery-key` Secret Manager value. Keep
   an independent owner-held copy in a password manager or offline safe before
   removing any temporary copy. Do not display the key or send it to anyone.
   The job decodes this secret to a private temporary file and deletes the file
   when it exits.
3. Create a dedicated runtime service account named `vata-recovery-job`. Grant
   it `roles/storage.bucketViewer` and `roles/storage.objectAdmin` on only the
   approved bucket, and `roles/secretmanager.secretAccessor` on only the two
   recovery secrets. Keep secret versions pinned in the job configuration; update
   the reference deliberately when rotating a secret.

The following commands create the runtime identity and scoped grants. Create the
two secret values through Secret Manager without entering them in a terminal
command or this chat.

```sh
BUCKET='bucket-quickstart_vata-511710'
JOB_SA="vata-recovery-job@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create vata-recovery-job --project="${PROJECT_ID}"
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${JOB_SA}" --role=roles/storage.bucketViewer \
  --project="${PROJECT_ID}"
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${JOB_SA}" --role=roles/storage.objectAdmin \
  --project="${PROJECT_ID}"
```

For the key, a trusted operator can create a private base64 file with
`umask 077; openssl rand -base64 32 > "$HOME/vata-recovery-key.b64"`, add that
file to Secret Manager, and download a separate owner-held copy before deleting
the temporary file. Never run `cat` on it. Create the secret if it does not
already exist, then add the file as a secret version:

```sh
gcloud secrets create vata-recovery-key \
  --replication-policy=automatic --project="${PROJECT_ID}"
gcloud secrets versions add vata-recovery-key \
  --data-file="$HOME/vata-recovery-key.b64" --project="${PROJECT_ID}"
```

Grant the runtime service account access to the two secret names (not the whole
project):

```sh
for SECRET in vata-recovery-source vata-recovery-key; do
  gcloud secrets add-iam-policy-binding "${SECRET}" \
    --member="serviceAccount:${JOB_SA}" \
    --role=roles/secretmanager.secretAccessor --project="${PROJECT_ID}"
done
```

Review the bucket's lifecycle, retention, public-access, and soft-delete
settings. Do not add a Cloud Storage lifecycle delete rule: it cannot check
whether a newer recovery point has been verified. The operator job performs
guarded retention after verification. Soft-delete retention may add storage
charges beyond the base estimate.

## Deploy and run the first copy

Deploy a single-task Cloud Run Job named `vata-recovery-daily` in `us-east4`,
using the image built above and the `vata-recovery-job` service account. Replace
the secret version numbers if the first active version is not `1`:

```sh
gcloud run jobs deploy vata-recovery-daily \
  --project="${PROJECT_ID}" --region="${RUN_REGION}" \
  --image="${IMAGE}" --service-account="${JOB_SA}" \
  --tasks=1 --parallelism=1 --max-retries=1 --task-timeout=12h \
  --cpu=1 --memory=1Gi \
  --set-env-vars="VATA_RECOVERY_GCS_BUCKET=${BUCKET}" \
  --set-secrets="VATA_RECOVERY_SOURCE_URL=vata-recovery-source:1,VATA_RECOVERY_KEY_B64=vata-recovery-key:1"
```

The job configuration is:

- `VATA_RECOVERY_GCS_BUCKET=bucket-quickstart_vata-511710`
- `VATA_RECOVERY_SOURCE_URL` from the pinned source-URL secret version
- `VATA_RECOVERY_KEY_B64` from the pinned key secret version
- One CPU, 1 GiB memory, one task, a 12-hour task timeout, and one retry

The container command already includes `daily --approve-sensitive-export`.
That flag is an operator acknowledgement only; the export permission and live
rehearsal permission must remain documented in the owner/operator's private
records. Cloud Run writes structured status to Cloud Logging only.

For the first live run, arrange and confirm the approved quiescence window:
pause scanner, gateway, scheduler, account/team, webhook, and direct database
writers; confirm the latest SQLite snapshots are committed to PostgreSQL and
preserve any dirty SQLite/WAL files separately. Then manually execute the job:

```sh
gcloud run jobs execute vata-recovery-daily \
  --project="${PROJECT_ID}" --region="${RUN_REGION}" --wait
```

Do not schedule recurring execution until the first off-project object has
downloaded and passed checksum comparison.

The successful job log includes the daily object name and SHA-256. Download that
encrypted object to a private operator directory and compare `sha256sum` with the
logged value. Keep the result privately without database rows or credentials.
Do not attach the archive to chat or place it in the repository.

## Schedule and ongoing checks

Create one Cloud Scheduler job after the first verified copy, scheduled for
`0 4 * * *` in `Etc/UTC`. Give its dedicated service account only
`roles/run.invoker` on `vata-recovery-daily`:

```sh
SCHEDULER_SA="vata-recovery-scheduler@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts create vata-recovery-scheduler --project="${PROJECT_ID}"
gcloud run jobs add-iam-policy-binding vata-recovery-daily \
  --project="${PROJECT_ID}" --region="${RUN_REGION}" \
  --member="serviceAccount:${SCHEDULER_SA}" --role=roles/run.invoker
gcloud scheduler jobs create http vata-recovery-daily \
  --project="${PROJECT_ID}" --location="${RUN_REGION}" \
  --schedule="0 4 * * *" --time-zone="Etc/UTC" \
  --uri="https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${RUN_REGION}/jobs/vata-recovery-daily:run" \
  --http-method=POST --oauth-service-account-email="${SCHEDULER_SA}"
```

The Scheduler calls:

```text
https://run.googleapis.com/v2/projects/vata-511710/locations/us-east4/jobs/vata-recovery-daily:run
```

Check Cloud Scheduler and Cloud Run execution logs for daily success, failures,
and recovery-point age. Do not add email or webhook notifications without new
approval. The job keeps monthly recovery points in a separate object prefix and
never prunes after a failed export or verification.

The owner has separately approved a live isolated restore rehearsal. Perform it
from a downloaded copy on a trusted isolated operator host, not against the
production database. Follow the restore, Clerk ownership preservation, and
tenant-isolation checks in
[independent-recovery.md](independent-recovery.md#isolated-restoration-never-replaces-the-existing-database).
