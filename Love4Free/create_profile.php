<?php
session_start();
include 'db.php';
include_once __DIR__ . '/helpers.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? '';
    $bio = $_POST['bio'] ?? '';
    $song = $_POST['song'] ?? '';
    $personality = $_POST['personality'] ?? '';
    $job = $_POST['job'] ?? '';
    $hobbies = $_POST['hobbies'] ?? '';
    $love = $_POST['love'] ?? '';
    $travel = $_POST['travel'] ?? '';
    $video = $_POST['video'] ?? '';
    $notes = $_POST['notes'] ?? '';
    $avatar = trim($_POST['avatar'] ?? '');
    $chromosomes = isset($_POST['chromosomes']) && in_array($_POST['chromosomes'], ['xx', 'xy', '3'], true) ? $_POST['chromosomes'] : null;
    $song_type = '';

    if (!empty($video)) {
        $video = youtube_to_embed($video);
        if (strpos($video, 'youtube.com/embed/') === false) $video = '';
    }
    
    if (!empty($song)) {
        if (strpos($song, 'spotify.com') !== false) {
            $song_type = 'spotify';
            $song = basename(parse_url($song, PHP_URL_PATH));
        } else {
            $embed = youtube_to_embed($song);
            if (strpos($embed, 'youtube.com/embed/') !== false) {
                $song_type = 'youtube';
                $song = $embed;
            }
        }
    }

    $stmt = $pdo->prepare("INSERT INTO profiles (name, bio, song, song_type, personality, job, hobbies, love, travel, video, notes, avatar, chromosomes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([$name, $bio, $song, $song_type, $personality, $job, $hobbies, $love, $travel, $video, $notes, $avatar, $chromosomes]);

    $_SESSION['user_id'] = $pdo->lastInsertId();

    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="theme-color" content="#831843">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23f472b6'><path d='M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z'/></svg>">
  <title>Create Your Profile - Love4Free</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .heart { color: #f472b6; }
    .btn-love { background: linear-gradient(135deg, #a21caf 0%, #be185d 100%); }
    .btn-love:hover { background: linear-gradient(135deg, #c026d3 0%, #e11d48 100%); }
  </style>
</head>
<body class="bg-gray-900 text-white min-h-screen p-4 pb-safe">
  <style>.pb-safe{padding-bottom:env(safe-area-inset-bottom,0);}</style>
  <div class="max-w-2xl mx-auto bg-gray-800 p-6 rounded-lg border border-gray-700">
    <h1 class="text-2xl font-bold mb-2">Create Your Dating Profile <span class="heart">♥</span></h1>
    <p class="text-gray-400 text-sm mb-6">Your love story starts here — tell the world what makes you wonderful!</p>
    
    <form method="POST" class="space-y-4">
      <div>
        <label class="block mb-2 font-medium">Your Name</label>
        <input type="text" name="name" required placeholder="The name they'll fall for..."
               class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
      </div>
      <div>
        <label class="block mb-2 font-medium">Chromosomes</label>
        <select name="chromosomes" class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
          <option value="">Prefer not to say</option>
          <option value="xx">XX</option>
          <option value="xy">XY</option>
          <option value="3">3 chromosomes</option>
        </select>
      </div>
      <div>
        <label class="block mb-2 font-medium">Avatar URL (e.g., Imgur link)</label>
        <input type="text" name="avatar" placeholder="https://i.imgur.com/..." 
               class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
      </div>
      <div>
        <label class="block mb-2 font-medium">Bio (Tell us about yourself)</label>
        <textarea name="bio" rows="3" required placeholder="What makes you unique? Share your sparkle..."
                  class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600"></textarea>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block mb-2 font-medium">Personality Type</label>
          <input type="text" name="personality" 
                 placeholder="e.g., INFP, Extrovert, Hopeless romantic"
                 class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
        </div>
        <div>
          <label class="block mb-2 font-medium">Occupation</label>
          <input type="text" name="job" placeholder="What do you do?"
                 class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
        </div>
      </div>
      <div>
        <label class="block mb-2 font-medium">Favorite Song (URL or name)</label>
        <input type="text" name="song" 
               placeholder="The song that says 'you' — Spotify or YouTube link"
               class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
      </div>
      <div>
        <label class="block mb-2 font-medium">Video Introduction (YouTube URL)</label>
        <input type="text" name="video" 
               placeholder="https://www.youtube.com/watch?v=... (optional)"
               class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
      </div>
      <div>
        <label class="block mb-2 font-medium">Hobbies & Interests</label>
        <textarea name="hobbies" rows="2" placeholder="What do you love to do?"
                  class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600"></textarea>
      </div>
      <div>
        <label class="block mb-2 font-medium">What You're Looking For</label>
        <textarea name="love" rows="2" placeholder="Your dream connection in a few words..."
                  class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600"></textarea>
      </div>
      <div>
        <label class="block mb-2 font-medium">Travel Preferences</label>
        <input type="text" name="travel" 
               placeholder="e.g., Beach lover, Mountain hiker, City explorer"
               class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600">
      </div>
      <div>
        <label class="block mb-2 font-medium">Private Notes (only you can see)</label>
        <textarea name="notes" rows="2" placeholder="Notes for yourself..."
                  class="w-full p-3 bg-gray-700 rounded focus:ring-2 focus:ring-pink-500 border border-gray-600"></textarea>
      </div>
      <button type="submit" 
              class="w-full py-3 btn-love rounded-lg hover:opacity-90 font-medium touch-manipulation active:opacity-80">
        Create Profile <span class="heart">♥</span>
      </button>
    </form>
  </div>
</body>
</html>