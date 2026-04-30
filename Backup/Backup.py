import os
import shutil
import argparse

def flatten_folder(source_dir, target_dir):
    """Move all files from source_dir (including subfolders) into a flat target_dir."""
    if not os.path.isdir(source_dir):
        print(f"Error: source directory does not exist: {source_dir}")
        return

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    file_counts = {}

    for root, _, files in os.walk(source_dir):
        for filename in files:
            if os.path.normpath(root) == os.path.normpath(target_dir):
                continue

            source_path = os.path.join(root, filename)
            base, ext = os.path.splitext(filename)

            new_filename = filename
            counter = file_counts.get(filename, 0)

            while os.path.exists(os.path.join(target_dir, new_filename)):
                counter += 1
                new_filename = f"{base}_{counter}{ext}"

            file_counts[filename] = counter

            target_path = os.path.join(target_dir, new_filename)
            shutil.move(source_path, target_path)
            print(f"Moved: {filename} -> {new_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Flatten a folder tree — move all files from subfolders into a single target directory."
    )
    parser.add_argument("source", help="Source directory to flatten")
    parser.add_argument("target", help="Target directory for all files")
    args = parser.parse_args()

    flatten_folder(args.source, args.target)
