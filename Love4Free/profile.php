<?php
session_start();
include 'db.php';
include_once __DIR__ . '/helpers.php';

$profile = null;
$isOwnProfile = false;
$success = isset($_GET['saved']) ? "Profile saved successfully!" : null;

if (isset($_GET['id'])) {
    $stmt = $pdo->prepare("SELECT * FROM profiles WHERE id = ?");
    $stmt->execute([$_GET['id']]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);
    $isOwnProfile = isset($_SESSION['user_id']) && $profile && $profile['id'] == $_SESSION['user_id'];
}

// Handle profile update
if ($isOwnProfile && $_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['gallery_type'])) {
    $bio = $_POST['bio'] ?? '';
    $song = $_POST['song'] ?? '';
    $song_type = $_POST['song_type'] ?? '';
    $personality = $_POST['personality'] ?? '';
    $job = $_POST['job'] ?? '';
    $hobbies = $_POST['hobbies'] ?? '';
    $love = $_POST['love'] ?? '';
    $travel = $_POST['travel'] ?? '';
    $video = $_POST['video'] ?? '';
    $notes = $_POST['notes'] ?? '';
    $avatar = $_POST['avatar'] ?? '';
    $chromosomes = isset($_POST['chromosomes']) && in_array($_POST['chromosomes'], ['xx', 'xy', '3'], true) ? $_POST['chromosomes'] : null;
    
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

    $stmt = $pdo->prepare("UPDATE profiles SET bio = ?, song = ?, song_type = ?, personality = ?, job = ?, hobbies = ?, love = ?, travel = ?, video = ?, notes = ?, avatar = ?, chromosomes = ? WHERE id = ?");
    $stmt->execute([$bio, $song, $song_type, $personality, $job, $hobbies, $love, $travel, $video, $notes, $avatar, $chromosomes, $_SESSION['user_id']]);
    header("Location: profile.php?id=" . $_SESSION['user_id'] . "&saved=1");
    exit;
}

// Handle gallery addition (only if gallery table exists)
if ($isOwnProfile && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gallery_type'])) {
    $type = $_POST['gallery_type'];
    $content = trim($_POST['gallery_content']);
    
    if (!empty($content)) {
        if ($type === 'video') {
            $content = youtube_to_embed($content);
            if (strpos($content, 'youtube.com/embed/') === false) $content = '';
        }
        try {
            $stmt = $pdo->prepare("INSERT INTO gallery (profile_id, type, content) VALUES (?, ?, ?)");
            $stmt->execute([$_SESSION['user_id'], $type, $content]);
            header("Location: profile.php?id=" . $_SESSION['user_id'] . "&saved=1");
            exit;
        } catch (PDOException $e) {
            // Gallery table may not exist
        }
    }
}

// Fetch gallery items (table may not exist on older installs)
$galleryItems = [];
if ($profile) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM gallery WHERE profile_id = ? ORDER BY created_at DESC");
        $stmt->execute([$profile['id']]);
        $galleryItems = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $galleryItems = [];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="theme-color" content="#831843">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23f472b6'><path d='M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z'/></svg>">
  <title><?php echo $profile ? htmlspecialchars($profile['name'] ?? '') . "'s Profile" : 'Profile Not Found'; ?> - Love4Free</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .heart { color: #f472b6; }
    .btn-love { background: linear-gradient(135deg, #a21caf 0%, #be185d 100%); }
    .btn-love:hover { background: linear-gradient(135deg, #c026d3 0%, #e11d48 100%); }
    </style>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="container mx-auto p-4 pb-safe max-w-6xl">
  <style>.pb-safe{padding-bottom:env(safe-area-inset-bottom,1rem);}</style>
    <a href="index.php" class="inline-block mb-4 text-pink-300 hover:text-pink-200 text-sm touch-manipulation">← Back to Wall <span class="heart">♥</span></a>
    <?php if ($profile): ?>
      <div class="flex flex-col lg:flex-row gap-6">
        <!-- Main Profile Info -->
        <div class="lg:w-2/3">
          <div class="bg-gray-800 p-6 rounded-lg">
            <div class="flex items-center mb-4">
              <?php 
              $avatarUrl = trim($profile['avatar'] ?? '');
              $hasValidAvatar = $avatarUrl !== '' && (strpos($avatarUrl, 'http://') === 0 || strpos($avatarUrl, 'https://') === 0);
              $initial = strtoupper(mb_substr(trim($profile['name'] ?? ''), 0, 1)) ?: '?';
              ?>
              <?php if ($hasValidAvatar): ?>
                <img src="<?php echo htmlspecialchars($avatarUrl); ?>" alt="" class="w-16 h-16 rounded-full mr-4 ring-2 ring-pink-500/30 object-cover" onerror="this.style.display='none'; this.nextElementSibling && this.nextElementSibling.classList.remove('hidden');">
                <span class="hidden w-16 h-16 rounded-full mr-4 ring-2 ring-pink-500/30 bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xl font-bold text-white"><?php echo htmlspecialchars($initial); ?></span>
              <?php else: ?>
                <span class="w-16 h-16 rounded-full mr-4 ring-2 ring-pink-500/30 bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xl font-bold text-white"><?php echo htmlspecialchars($initial); ?></span>
              <?php endif; ?>
              <div>
                <h1 class="text-3xl font-bold"><?php echo htmlspecialchars($profile['name'] ?? ''); ?> <span class="heart">♥</span></h1>
                <?php if (!$isOwnProfile): ?>
                  <p class="text-gray-400 text-sm">Check out their profile — maybe it's a match!</p>
                <?php endif; ?>
              </div>
            </div>
            <?php if ($success): ?>
              <p class="text-pink-300 mb-4"><?php echo $success; ?> <span class="heart">♥</span></p>
            <?php endif; ?>
            
            <?php if ($isOwnProfile): ?>
              <form method="POST" class="space-y-4">
                <div>
                  <label class="block mb-2 font-medium">Chromosomes</label>
                  <select name="chromosomes" class="w-full p-3 bg-gray-700 rounded">
                    <option value="">Prefer not to say</option>
                    <option value="xx"<?php echo ($profile['chromosomes'] ?? '') === 'xx' ? ' selected' : ''; ?>>XX</option>
                    <option value="xy"<?php echo ($profile['chromosomes'] ?? '') === 'xy' ? ' selected' : ''; ?>>XY</option>
                    <option value="3"<?php echo ($profile['chromosomes'] ?? '') === '3' ? ' selected' : ''; ?>>3 chromosomes</option>
                  </select>
                </div>
                <div>
                  <label class="block mb-2 font-medium">Avatar URL (e.g., Imgur link)</label>
                  <input type="text" name="avatar" value="<?php echo htmlspecialchars($profile['avatar'] ?? ''); ?>" 
                         class="w-full p-3 bg-gray-700 rounded">
                </div>
                <div>
                  <label class="block mb-2 font-medium">Bio</label>
                  <textarea name="bio" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['bio'] ?? ''); ?></textarea>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label class="block mb-2 font-medium">Personality Type</label>
                    <input type="text" name="personality" value="<?php echo htmlspecialchars($profile['personality'] ?? ''); ?>" 
                           class="w-full p-3 bg-gray-700 rounded">
                  </div>
                  <div>
                    <label class="block mb-2 font-medium">Occupation</label>
                    <input type="text" name="job" value="<?php echo htmlspecialchars($profile['job'] ?? ''); ?>" 
                           class="w-full p-3 bg-gray-700 rounded">
                  </div>
                </div>
                <div>
                  <label class="block mb-2 font-medium">Favorite Song (URL or name)</label>
                  <?php
                  $songDisplay = $profile['song'] ?? '';
                  if ($profile['song_type'] === 'spotify' && $songDisplay) {
                      $songDisplay = 'https://open.spotify.com/track/' . $songDisplay;
                  } elseif ($profile['song_type'] === 'youtube' && $songDisplay) {
                      $songDisplay = preg_replace('#^https?://(?:www\.)?youtube\.com/embed/([a-zA-Z0-9_-]+).*#', 'https://www.youtube.com/watch?v=$1', $songDisplay);
                  }
                  ?>
                  <input type="text" name="song" value="<?php echo htmlspecialchars($songDisplay); ?>" 
                         placeholder="Spotify or YouTube link, or song name"
                         class="w-full p-3 bg-gray-700 rounded">
                </div>
                <div>
                  <label class="block mb-2 font-medium">Video Introduction (YouTube URL)</label>
                  <input type="text" name="video" value="<?php echo htmlspecialchars(preg_replace('#^https?://(?:www\.)?youtube\.com/embed/([a-zA-Z0-9_-]+).*#', 'https://www.youtube.com/watch?v=$1', $profile['video'] ?? '')); ?>" 
                         placeholder="https://www.youtube.com/watch?v=..."
                         class="w-full p-3 bg-gray-700 rounded">
                </div>
                <div>
                  <label class="block mb-2 font-medium">Travel Preferences</label>
                  <input type="text" name="travel" value="<?php echo htmlspecialchars($profile['travel'] ?? ''); ?>" 
                         placeholder="e.g., Beach lover, Mountain hiker"
                         class="w-full p-3 bg-gray-700 rounded">
                </div>
                <div>
                  <label class="block mb-2 font-medium">Hobbies & Interests</label>
                  <textarea name="hobbies" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['hobbies'] ?? ''); ?></textarea>
                </div>
                <div>
                  <label class="block mb-2 font-medium">What You're Looking For</label>
                  <textarea name="love" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['love'] ?? ''); ?></textarea>
                </div>
                <div>
                  <label class="block mb-2 font-medium">Private Notes (only you can see)</label>
                  <textarea name="notes" rows="2" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['notes'] ?? ''); ?></textarea>
                </div>
                <button type="submit" class="px-6 py-3 btn-love rounded-lg hover:opacity-90 font-medium touch-manipulation active:opacity-80">
                  Save with love <span class="heart">♥</span>
                </button>
              </form>
            <?php else: ?>
              <div class="space-y-4">
                <p class="text-lg"><?php echo nl2br(htmlspecialchars($profile['bio'] ?? '')); ?></p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <?php if (!empty($profile['chromosomes'])): ?>
                  <div>
                    <h3 class="font-bold text-pink-300">Chromosomes</h3>
                    <p><?php echo $profile['chromosomes'] === '3' ? '3 chromosomes' : strtoupper(htmlspecialchars($profile['chromosomes'] ?? '')); ?></p>
                  </div>
                  <?php endif; ?>
                  <div>
                    <h3 class="font-bold text-pink-300">Personality</h3>
                    <p><?php echo ($profile['personality'] ?? '') !== '' ? htmlspecialchars($profile['personality']) : 'Not specified'; ?></p>
                  </div>
                  <div>
                    <h3 class="font-bold text-pink-300">Occupation</h3>
                    <p><?php echo ($profile['job'] ?? '') !== '' ? htmlspecialchars($profile['job']) : 'Not specified'; ?></p>
                  </div>
                </div>
                <div>
                  <h3 class="font-bold text-pink-300">Hobbies & Interests</h3>
                  <p><?php echo ($profile['hobbies'] ?? '') !== '' ? nl2br(htmlspecialchars($profile['hobbies'])) : 'Not specified'; ?></p>
                </div>
                <div>
                  <h3 class="font-bold text-pink-300">Looking For</h3>
                  <p><?php echo ($profile['love'] ?? '') !== '' ? nl2br(htmlspecialchars($profile['love'])) : 'Not specified'; ?></p>
                </div>
              </div>
            <?php endif; ?>
          </div>

          <!-- Gallery Section -->
          <div class="mt-6 bg-gray-800 p-6 rounded-lg">
            <h2 class="text-xl font-bold mb-4">Gallery <span class="heart">♥</span></h2>
            <?php if ($isOwnProfile): ?>
              <form method="POST" class="space-y-4 mb-6">
                <div>
                  <label class="block mb-2 font-medium">Add to Gallery</label>
                  <select name="gallery_type" class="w-full p-3 bg-gray-700 rounded mb-2">
                    <option value="image">Image (URL)</option>
                    <option value="video">Video (YouTube URL)</option>
                    <option value="note">Note (Text)</option>
                  </select>
                  <textarea name="gallery_content" rows="2" placeholder="Enter URL or text" 
                            class="w-full p-3 bg-gray-700 rounded"></textarea>
                </div>
                <button type="submit" class="px-6 py-3 btn-love rounded-lg hover:opacity-90 font-medium touch-manipulation">
                  Add to Gallery <span class="heart">♥</span>
                </button>
              </form>
            <?php endif; ?>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <?php foreach ($galleryItems as $item): 
                $itemContent = trim($item['content'] ?? '');
                $isValidUrl = $itemContent !== '' && (strpos($itemContent, 'http://') === 0 || strpos($itemContent, 'https://') === 0);
                $isValidEmbed = $item['type'] === 'video' && strpos($itemContent, 'youtube.com/embed/') !== false;
                if ($item['type'] === 'image' && !$isValidUrl) continue;
                if ($item['type'] === 'video' && !$isValidEmbed) continue;
                if ($item['type'] === 'note' && $itemContent === '') continue;
              ?>
                <div class="p-3 bg-gray-700 rounded-lg">
                  <?php if ($item['type'] === 'image'): ?>
                    <img src="<?php echo htmlspecialchars($itemContent); ?>" alt="Gallery" class="w-full h-40 object-cover rounded" onerror="this.style.display='none';">
                  <?php elseif ($item['type'] === 'video'): ?>
                    <iframe src="<?php echo htmlspecialchars($itemContent); ?>" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen class="w-full h-40 rounded aspect-video"></iframe>
                  <?php else: ?>
                    <p class="text-gray-300"><?php echo nl2br(htmlspecialchars($itemContent)); ?></p>
                  <?php endif; ?>
                </div>
              <?php endforeach; ?>
            </div>
          </div>
        </div>
        
        <!-- Media Section -->
        <div class="lg:w-1/3 space-y-6">
          <?php 
          $profileVideo = trim($profile['video'] ?? '');
          $hasVideo = $profileVideo !== '' && strpos($profileVideo, 'youtube.com/embed/') !== false;
          if (!$hasVideo && $profileVideo !== '') { $profileVideo = youtube_to_embed($profileVideo); $hasVideo = strpos($profileVideo, 'youtube.com/embed/') !== false; }
          ?>
          <?php if ($hasVideo): ?>
            <div class="bg-gray-800 p-4 rounded-lg">
              <h2 class="text-xl font-bold mb-3">Video <span class="heart">♥</span></h2>
              <div class="aspect-video w-full">
                <iframe src="<?php echo htmlspecialchars($profileVideo); ?>" 
                        frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen
                        class="w-full h-64 rounded"></iframe>
              </div>
            </div>
          <?php endif; ?>
          <?php if (!empty($profile['song'])): ?>
            <div class="bg-gray-800 p-4 rounded-lg">
              <h2 class="text-xl font-bold mb-3">Favorite Music <span class="heart">♥</span></h2>
              <?php if ($profile['song_type'] === 'spotify'): ?>
                <iframe src="https://open.spotify.com/embed/track/<?php echo htmlspecialchars($profile['song'] ?? ''); ?>" 
                        width="100%" height="80" frameborder="0" 
                        allowtransparency="true" allow="encrypted-media"
                        class="rounded"></iframe>
              <?php elseif ($profile['song_type'] === 'youtube'): ?>
                <?php $songEmbed = (strpos($profile['song'], 'youtube.com/embed/') !== false) ? $profile['song'] : youtube_to_embed($profile['song']); ?>
                <?php if (strpos($songEmbed, 'youtube.com/embed/') !== false): ?>
                <iframe src="<?php echo htmlspecialchars($songEmbed ?? ''); ?>" width="100%" height="80" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen class="rounded"></iframe>
                <?php else: ?>
                <p class="text-lg"><?php echo htmlspecialchars($profile['song'] ?? ''); ?></p>
                <?php endif; ?>
              <?php else: ?>
                <p class="text-lg"><?php echo htmlspecialchars($profile['song'] ?? ''); ?></p>
              <?php endif; ?>
            </div>
          <?php endif; ?>
        </div>
      </div>
    <?php else: ?>
      <div class="bg-gray-800 p-6 rounded-lg text-center border border-gray-700">
        <h1 class="text-3xl font-bold mb-4">Profile Not Found <span class="heart">♥</span></h1>
        <p class="text-lg text-gray-300">The profile you're looking for isn't here — but don't give up on love! Head back and explore other matches.</p>
        <a href="index.php" class="mt-4 inline-block px-6 py-2 btn-love rounded-lg hover:opacity-90">
          Return Home <span class="heart">♥</span>
        </a>
      </div>
    <?php endif; ?>
  </div>
</body>
</html>