import os
import subprocess

INPUT_DIR = "./input"
OUTPUT_DIR = "./output"

# Path to your FFmpeg executable
FFMPEG_PATH = r"C:\Users\Admin\Downloads\ffmpeg-8.1-full_build\ffmpeg-8.1-full_build\bin\ffmpeg.exe"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def mp3_to_mp4_ffmpeg(mp3_filename, default_bg_color="black", resolution="1280x720"):
    """
    Convert MP3 to MP4:
      - Uses matching image if it exists (e.g. song.mp3 + song.jpg)
      - Otherwise uses solid color background
    """
    mp3_path = os.path.join(INPUT_DIR, mp3_filename)
    base_name = os.path.splitext(mp3_filename)[0]
    output_path = os.path.join(OUTPUT_DIR, f"{base_name}.mp4")

    if not os.path.exists(mp3_path):
        print(f"❌ MP3 not found: {mp3_path}")
        return

    if not os.path.exists(FFMPEG_PATH):
        print(f"❌ FFmpeg not found at: {FFMPEG_PATH}")
        return

    print(f"🎵 Processing: {mp3_filename}")

    # Check for matching image: song.mp3 → song.jpg, song.png, song.jpeg
    image_path = None
    for ext in [".jpg", ".jpeg", ".png", ".JPG", ".JPEG", ".PNG"]:
        possible_image = os.path.join(INPUT_DIR, base_name + ext)
        if os.path.exists(possible_image):
            image_path = possible_image
            print(f"   → Using background image: {os.path.basename(image_path)}")
            break

    # Build FFmpeg command
    cmd = [FFMPEG_PATH, "-y"]

    if image_path:
        # Use image as background
        cmd.extend(["-loop", "1", "-i", image_path])           # static image
        cmd.extend(["-i", mp3_path])                           # audio
        cmd.extend(["-c:v", "libx264", "-tune", "stillimage"])
    else:
        # Use solid color as background
        cmd.extend(["-f", "lavfi", "-i", f"color=c={default_bg_color}:s={resolution}"])
        cmd.extend(["-i", mp3_path])
        cmd.extend(["-c:v", "libx264", "-tune", "stillimage"])

    # Common settings
    cmd.extend([
        "-c:a", "aac",
        "-b:a", "192k",
        "-pix_fmt", "yuv420p",
        "-shortest",
        output_path
    ])

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ Saved: {output_path}\n")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error processing {mp3_filename}:")
        print(e.stderr)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def mp3_to_mp4_folder_ffmpeg(default_bg_color="black", resolution="1280x720"):
    """Convert all MP3 files"""
    if not os.path.exists(INPUT_DIR):
        print(f"❌ Input folder not found: {INPUT_DIR}")
        return

    mp3_files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith(".mp3")]

    if not mp3_files:
        print("⚠️ No MP3 files found in ./input")
        return

    print(f"Found {len(mp3_files)} MP3 file(s). Starting conversion...\n")

    for mp3_file in mp3_files:
        mp3_to_mp4_ffmpeg(mp3_file, default_bg_color=default_bg_color, resolution=resolution)

    print("🎉 All conversions completed!")


# ======================
# Run the script
# ======================
if __name__ == "__main__":
    # Change default color here if no image is found
    mp3_to_mp4_folder_ffmpeg(default_bg_color="black", resolution="1280x720")
