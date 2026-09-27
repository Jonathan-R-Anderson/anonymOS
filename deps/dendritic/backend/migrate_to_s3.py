import os
import sys
import datetime

# Ensure we can import from the root directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shared import app, db
from model.Media import Media, S3Storage, FolderStorage, MissingAttachmentError

def find_uploads_dir():
    print("[migration] PERFORMING SCORCHED EARTH SEARCH...")
    for root, dirs, files in os.walk("/maniwani"):
        if files:
            print(f"[migration] Found files in {root}: {files[:5]}")
            if any(f.endswith((".svg", ".jpg", ".png")) for f in files):
                 print(f"[migration] !!! MEDIA DIRECTORY DETECTED: {root}")
                 return root
    
    for root, dirs, files in os.walk("/data"):
        if files:
            print(f"[migration] Found files in {root}: {files[:5]}")
            if any(f.endswith((".svg", ".jpg", ".png")) for f in files):
                 print(f"[migration] !!! MEDIA DIRECTORY DETECTED: {root}")
                 return root

    print("[migration] SCORCHED EARTH FINISHED. NO MEDIA FOUND.")
    return None
    return None

def migrate():
    with app.app_context():
        if app.config.get("STORAGE_PROVIDER") != "S3":
            print("[migration] Storage provider is not S3. Skipping migration.")
            return

        s3 = S3Storage()
        folder = FolderStorage()
        
        report_path = "/maniwani/migration_report.txt"
        with open(report_path, "w") as report:
            report.write(f"Migration started at {datetime.datetime.utcnow()}\n")
            
            s3 = S3Storage()
            folder = FolderStorage()
            
            # 1. Wait for S3 to be ready
            try:
                report.write(f"Verifying S3 connectivity to {s3._endpoint}...\n")
                s3_ready = False
                for _ in range(10):
                    try:
                        s3._get_bucket(s3._ATTACHMENT_BUCKET)
                        s3_ready = True
                        break
                    except Exception as e:
                        report.write(f"Waiting for S3... ({e})\n")
                        import time
                        time.sleep(2)
                if not s3_ready:
                    report.write("S3 connection failed after 10 attempts. Aborting migration.\n")
                    return
            except Exception as e:
                report.write(f"S3 setup error: {e}\n")
                return

            report.write(f"Initial UPLOAD_FOLDER: {folder._upload_folder} (Absolute: {os.path.abspath(folder._upload_folder)})\n")
            if os.path.exists(folder._upload_folder):
                report.write(f"UPLOAD_FOLDER exists. Items: {os.listdir(folder._upload_folder)[:20]}\n")
            else:
                report.write("UPLOAD_FOLDER does not exist at initial path.\n")

            found_dir = find_uploads_dir()
            if found_dir:
                folder._upload_folder = found_dir
                report.write(f"FINAL UPLOAD_FOLDER: {folder._upload_folder}\n")
            
            target_dir = folder._upload_folder
            medias = db.session.query(Media).all()
            report.write(f"Checking {len(medias)} media records for migration...\n")

            migrated_count = 0
            found_on_disk = 0
            already_on_s3 = 0
            for media in medias:
                try:
                    # Check if exists on S3
                    s3.read_attachment_bytes(media.id, media.ext)
                    already_on_s3 += 1
                    continue
                except Exception:
                    # Not on S3, try to find on disk
                    data = None
                    paths_to_try = [
                        os.path.join(folder._upload_folder, f"{media.id}.{media.ext}"),
                        os.path.join(folder._upload_folder, "attachments", f"{media.id}.{media.ext}"),
                        os.path.join(folder._upload_folder, f"media-{media.id}.{media.ext}"),
                        os.path.join(folder._upload_folder, "attachments", f"media-{media.id}.{media.ext}"),
                        # Absolute fallbacks
                        f"/maniwani/uploads/{media.id}.{media.ext}",
                        f"/maniwani/uploads/attachments/{media.id}.{media.ext}",
                    ]
                    for p in paths_to_try:
                        if os.path.exists(p):
                            found_on_disk += 1
                            with open(p, "rb") as f: data = f.read()
                            break
                    
                    if data:
                        report.write(f"Migrating attachment {media.id}.{media.ext} to S3...\n")
                        import io
                        s3._write_attachment(io.BytesIO(data), media.id, media.ext)
                        migrated_count += 1
            
            report.write(f"Summary: Medias={len(medias)}, AlreadyOnS3={already_on_s3}, FoundOnDisk={found_on_disk}, Migrated={migrated_count}\n")
            report.write(f"Migration finished at {datetime.datetime.utcnow()}\n")
        print(f"[migration] Completed scan. Report at {report_path}")

if __name__ == "__main__":
    migrate()
