<?php
session_start();
include 'db.php';
include_once __DIR__ . '/helpers.php';

// Ensure wall_posts table exists (for existing installs that were updated)
try {
    $pdo->query("SELECT 1 FROM wall_posts LIMIT 1");
} catch (PDOException $e) {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS wall_posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            profile_id INT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        )
    ");
}

$cooldownPeriod = 30;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
    if (isset($_SESSION['user_id'])) {
        $stmt = $pdo->prepare("SELECT id, name, avatar FROM profiles WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $currentTime = time();
            $content = trim($_POST['content']);

            if (!isset($_SESSION['last_post_time'])) {
                $_SESSION['last_post_time'] = 0;
            }
            if (!isset($_SESSION['last_post_content'])) {
                $_SESSION['last_post_content'] = '';
            }

            $timeSinceLastPost = $currentTime - $_SESSION['last_post_time'];
            if ($timeSinceLastPost < $cooldownPeriod) {
                $error = "Please wait " . ($cooldownPeriod - $timeSinceLastPost) . " seconds before posting again.";
            } elseif ($content === $_SESSION['last_post_content']) {
                $error = "You cannot post the same message twice in a row.";
            } elseif (!empty($content)) {
                try {
                    $stmt = $pdo->prepare("INSERT INTO wall_posts (profile_id, content) VALUES (?, ?)");
                    $stmt->execute([$user['id'], $content]);
                    $_SESSION['last_post_time'] = $currentTime;
                    $_SESSION['last_post_content'] = $content;
                    $success = "Posted with love! ♥";
                } catch (PDOException $e) {
                    $error = "Could not post. The wall may not be set up yet.";
                }
            } else {
                $error = "Post content cannot be empty.";
            }
        } else {
            $error = "User profile not found.";
        }
    } else {
        $error = "Create a profile to post on the wall.";
    }
}

$userProfile = null;
if (isset($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("SELECT * FROM profiles WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);
} else {
    // Auto-create a guest profile so new visitors can post immediately
    try {
        $guestName = generate_guest_name($pdo);
        $stmt = $pdo->prepare("INSERT INTO profiles (name, bio) VALUES (?, '')");
        $stmt->execute([$guestName]);
        $_SESSION['user_id'] = (int) $pdo->lastInsertId();
        $stmt = $pdo->prepare("SELECT * FROM profiles WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $userProfile = null;
    }
}

// Load wall posts from database (everyone sees the same wall)
$wallPosts = [];
try {
    $stmt = $pdo->query("
        SELECT p.id, p.profile_id, p.content, p.created_at,
               pr.name AS user, pr.avatar
        FROM wall_posts p
        INNER JOIN profiles pr ON pr.id = p.profile_id
        ORDER BY p.created_at ASC
        LIMIT 200
    ");
    $wallPosts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($wallPosts as &$row) {
        $row['time'] = date('H:i', strtotime($row['created_at']));
    }
    unset($row);
} catch (PDOException $e) {
    $wallPosts = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="theme-color" content="#831843">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23f472b6'><path d='M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z'/></svg>">
  <title>Love4Free - Your Spotlight</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --bg-deep: #1a0f1a;
      --bg-card: rgba(38, 24, 38, 0.85);
      --bg-sidebar: rgba(30, 18, 35, 0.95);
      --border-soft: rgba(244, 114, 182, 0.15);
      --text-muted: #c4b5c9;
      --accent: #f472b6;
      --accent-deep: #be185d;
    }
    body {
      font-family: 'Outfit', system-ui, sans-serif;
      background: radial-gradient(ellipse 120% 80% at 50% 0%, #2d1b2e 0%, #1a0f1a 50%, #120b12 100%);
      min-height: 100vh;
    }
    .player-container { height: calc(100vh - 4rem); }
    .posts-container { height: calc(100vh - 8rem); }
    @media (max-width: 767px) {
      .player-container { height: auto; min-height: 0; }
      .posts-container { height: calc(100vh - 14rem); min-height: 180px; padding-bottom: 5rem; }
      .post-form-mobile { position: fixed; bottom: 0; left: 0; right: 0; z-index: 30; padding: 0.75rem 1rem; padding-bottom: max(0.75rem, env(safe-area-inset-bottom)); }
    }
    @media (min-width: 768px) {
      .post-form-mobile { position: static; }
    }
    .heart { color: var(--accent); }
    .btn-love {
      background: linear-gradient(135deg, #c026d3 0%, #db2777 50%, #be185d 100%);
      box-shadow: 0 4px 14px rgba(190, 24, 93, 0.4);
    }
    .btn-love:hover { filter: brightness(1.1); box-shadow: 0 6px 20px rgba(190, 24, 93, 0.5); }
    .card-soft {
      background: var(--bg-card);
      border: 1px solid var(--border-soft);
      border-radius: 1rem;
      backdrop-filter: blur(8px);
    }
    .sidebar-panel {
      background: var(--bg-sidebar);
      border-color: var(--border-soft);
      backdrop-filter: blur(12px);
    }
    .input-soft {
      background: rgba(50, 30, 50, 0.8);
      border: 1px solid var(--border-soft);
      border-radius: 0.75rem;
    }
    .input-soft:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(244, 114, 182, 0.2);
    }
    .avatar-initials {
      width: 2.5rem;
      height: 2.5rem;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      font-size: 0.875rem;
      background: linear-gradient(135deg, #c026d3, #be185d);
      color: white;
    }
    .match-name { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    /* Hide Tailwind CDN dev/deprecation banner if injected */
    body > div[data-tailwind-banner] { display: none !important; }
  </style>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      [].forEach.call(document.body.children, function(el) {
        if (el.nodeType === 1 && el.tagName === 'DIV' && (el.textContent || '').toLowerCase().indexOf('deprecated') !== -1 && !el.querySelector('[id="posts"]') && !el.querySelector('.sidebar-panel')) {
          el.style.setProperty('display', 'none', 'important');
        }
      });
    });
  </script>
</head>
<body class="text-white flex flex-col md:flex-row h-screen overflow-hidden">
  <!-- Mobile header: title + Edit Profile when logged in -->
  <header class="md:hidden flex-shrink-0 px-4 py-3 sidebar-panel border-b flex items-center justify-between gap-3">
    <h1 class="text-lg font-bold tracking-tight">Love4Free <span class="heart">♥</span></h1>
    <?php if ($userProfile): ?>
    <a href="profile.php?id=<?php echo (int)$_SESSION['user_id']; ?>" class="px-3 py-1.5 btn-love rounded-lg text-sm font-medium whitespace-nowrap">Edit Profile <span class="heart">♥</span></a>
    <?php endif; ?>
  </header>
  <!-- Music Player Sidebar -->
  <div class="order-2 md:order-1 w-full md:w-64 flex-shrink-0 sidebar-panel flex flex-col player-container border-b md:border-r border-r">
    <details id="details-player" class="group flex flex-col flex-1" style="min-height:0">
      <summary class="md:hidden cursor-pointer p-4 font-bold text-xl border-b list-none flex items-center justify-between border-[var(--border-soft)]">
        Now Playing
        <span class="text-[var(--text-muted)] group-open:rotate-180 transition-transform">▼</span>
      </summary>
      <div class="p-4 flex flex-col flex-1" style="min-height:0">
    <h2 class="text-xl font-bold mb-3 hidden md:block tracking-tight">Now Playing <span class="heart">♥</span></h2>
    <div id="player-content" class="flex-1 text-[var(--text-muted)]">
      <?php if ($userProfile): ?>
        <?php if (!empty($userProfile['avatar'])): ?>
          <img src="<?php echo htmlspecialchars($userProfile['avatar']); ?>" alt="" class="w-16 h-16 rounded-full mb-4 object-cover ring-2 ring-white/10">
        <?php endif; ?>
        <?php if (!empty($userProfile['song'])): ?>
          <?php if ($userProfile['song_type'] === 'spotify'): ?>
            <iframe src="https://open.spotify.com/embed/track/<?php echo htmlspecialchars(basename($userProfile['song'])); ?>" 
                    width="100%" height="80" frameborder="0" allowtransparency="true" 
                    allow="encrypted-media" class="mb-4 rounded-lg"></iframe>
          <?php elseif ($userProfile['song_type'] === 'youtube'): ?>
            <?php $ytEmbed = (strpos($userProfile['song'], 'youtube.com/embed/') !== false) ? $userProfile['song'] : youtube_to_embed($userProfile['song']); ?>
            <?php if (strpos($ytEmbed, 'youtube.com/embed/') !== false): ?>
            <iframe src="<?php echo htmlspecialchars($ytEmbed); ?>" width="100%" height="120" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen class="mb-4 rounded-lg w-full aspect-video max-h-32"></iframe>
            <?php else: ?>
            <p class="text-sm mb-2 break-words"><?php echo htmlspecialchars($userProfile['song']); ?></p>
            <?php endif; ?>
          <?php else: ?>
            <p class="text-sm mb-2 break-words"><?php echo htmlspecialchars($userProfile['song']); ?></p>
          <?php endif; ?>
        <?php else: ?>
          <p class="text-sm opacity-80">No music playing</p>
        <?php endif; ?>
      <?php else: ?>
        <p class="text-sm opacity-80">No music playing</p>
      <?php endif; ?>
    </div>
    <?php if ($userProfile): ?>
      <a href="profile.php?id=<?php echo (int)$_SESSION['user_id']; ?>" class="mt-4 px-4 py-2.5 btn-love rounded-xl text-center font-medium text-sm">
        Edit Profile <span class="heart">♥</span>
      </a>
    <?php else: ?>
      <a href="create_profile.php" class="mt-auto px-4 py-2.5 btn-love rounded-xl text-center font-medium text-sm">
        Create Profile <span class="heart">♥</span>
      </a>
    <?php endif; ?>
      </div>
    </details>
  </div>

  <!-- Main Content -->
  <div class="order-1 md:order-2 flex-1 flex flex-col min-w-0">
    <!-- Wall Posts -->
    <div id="wall-scroll" class="flex-1 overflow-y-auto p-5 md:p-6 posts-container">
      <h2 class="text-2xl font-bold mb-1 tracking-tight">Love4Free Wall <span class="heart">♥</span></h2>
      <p class="text-sm text-[var(--text-muted)] mb-5">Share a thought or say hi to your matches.</p>
      <?php if (isset($error)): ?>
        <p class="text-rose-300 mb-4 text-sm"><?php echo htmlspecialchars($error); ?></p>
      <?php elseif (isset($success)): ?>
        <p class="text-pink-300 mb-4 text-sm"><?php echo htmlspecialchars($success); ?></p>
      <?php endif; ?>
      <?php if (!empty($_GET['term'])): ?>
        <a href="index.php" class="mb-4 inline-block px-4 py-2 btn-love rounded-xl hover:opacity-90 text-sm font-medium">← Back to Wall <span class="heart">♥</span></a>
      <?php endif; ?>
      <div id="posts" class="space-y-4">
        <?php if (empty($wallPosts)): ?>
          <div class="card-soft p-8 text-center">
            <p class="text-[var(--text-muted)] mb-2">No posts yet.</p>
            <p class="text-sm opacity-80">Be the first to share something sweet! ♥</p>
          </div>
        <?php endif; ?>
        <?php foreach ($wallPosts as $post): ?>
          <article class="card-soft p-4 flex items-start gap-4 hover:border-pink-500/30 transition-colors">
            <a href="profile.php?id=<?php echo (int)$post['profile_id']; ?>" class="flex-shrink-0">
              <?php if (!empty($post['avatar'])): ?>
                <img src="<?php echo htmlspecialchars($post['avatar']); ?>" alt="" class="w-12 h-12 rounded-full object-cover ring-2 ring-white/10">
              <?php else: ?>
                <span class="avatar-initials w-12 h-12 text-base"><?php echo strtoupper(mb_substr(trim($post['user']), 0, 1)) ?: '?'; ?></span>
              <?php endif; ?>
            </a>
            <div class="flex-1 min-w-0">
              <div class="flex flex-wrap justify-between items-center gap-2">
                <a href="profile.php?id=<?php echo (int)$post['profile_id']; ?>" class="font-semibold text-pink-200 hover:text-white transition-colors">
                  <?php echo htmlspecialchars($post['user']); ?>
                </a>
                <span class="text-xs text-[var(--text-muted)]"><?php echo $post['time']; ?></span>
              </div>
              <?php
              $postContent = $post['content'];
              $ytIds = youtube_extract_ids($postContent);
              $textOnly = trim(spotify_strip_from_text(youtube_strip_from_text($postContent)));
              $spotifyEmbeds = spotify_extract_embeds($post['content']);
              ?>
              <?php if ($textOnly !== ''): ?>
              <p class="mt-1.5 text-[var(--text-muted)] leading-relaxed break-words"><?php echo htmlspecialchars($textOnly); ?></p>
              <?php endif; ?>
              <?php foreach ($ytIds as $vid): ?>
              <div class="mt-2 rounded-lg overflow-hidden w-full max-w-md aspect-video">
                <iframe src="https://www.youtube.com/embed/<?php echo htmlspecialchars($vid); ?>" class="w-full h-full" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
              </div>
              <?php endforeach; ?>
              <?php foreach ($spotifyEmbeds as $sp): ?>
              <div class="mt-2 rounded-lg overflow-hidden w-full max-w-md">
                <iframe src="https://open.spotify.com/embed/<?php echo htmlspecialchars($sp['type']); ?>/<?php echo htmlspecialchars($sp['id']); ?>" width="100%" height="<?php echo $sp['type'] === 'track' ? '80' : '152'; ?>" frameborder="0" allowtransparency="true" allow="encrypted-media" class="rounded-lg"></iframe>
              </div>
              <?php endforeach; ?>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
    </div>
    
    <!-- Post area: form if has profile, else prompt — fixed at bottom on mobile so it's always visible -->
    <?php if (empty($_GET['term'])): ?>
      <?php if ($userProfile): ?>
      <div class="post-form-mobile p-4 border-t border-[var(--border-soft)] bg-[var(--bg-sidebar)]/95 backdrop-blur">
        <form method="POST" class="flex gap-2">
          <input type="text" name="content" placeholder="Share something sweet... ♥" 
                 class="flex-1 min-w-0 p-3 input-soft focus:outline-none text-white placeholder:text-gray-500" aria-label="Post message">
          <button type="submit" class="px-5 py-3 btn-love rounded-xl touch-manipulation font-medium text-sm">
            Post <span class="heart">♥</span>
          </button>
        </form>
      </div>
      <?php else: ?>
      <div class="post-form-mobile p-4 border-t border-[var(--border-soft)] bg-[var(--bg-sidebar)]/95 backdrop-blur text-center">
        <p class="text-[var(--text-muted)] text-sm mb-2">Create a profile to post on the wall.</p>
        <a href="create_profile.php" class="inline-block px-5 py-2.5 btn-love rounded-xl font-medium text-sm">Create Profile <span class="heart">♥</span></a>
      </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>

  <!-- Right Sidebar - User Profiles -->
  <div class="order-3 w-full md:w-80 flex-shrink-0 sidebar-panel overflow-y-auto border-t md:border-l">
    <details id="details-find">
      <summary class="md:hidden cursor-pointer p-4 font-bold text-xl border-b list-none flex items-center justify-between border-[var(--border-soft)]">
        Find Your Match
        <span class="text-[var(--text-muted)] details-find-arrow">▼</span>
      </summary>
      <div class="p-4">
    <h2 class="text-xl font-bold mb-1 tracking-tight">Find Your Match <span class="heart">♥</span></h2>
    <p class="text-sm text-[var(--text-muted)] mb-4">Browse profiles and find someone special.</p>
    <form method="GET" class="mb-4 flex gap-2">
      <input type="text" name="term" placeholder="Find someone special..." 
             class="flex-1 min-w-0 p-3 input-soft focus:outline-none text-white placeholder:text-gray-500 rounded-l-xl">
      <button type="submit" class="px-4 py-3 btn-love rounded-r-xl touch-manipulation font-medium text-sm">
        Search <span class="heart">♥</span>
      </button>
    </form>
    <?php
    $query = "SELECT id, name, song, song_type, avatar FROM profiles";
    $params = [];
    if (!empty($_GET['term'])) {
        $query .= " WHERE (name LIKE ? OR bio LIKE ? OR hobbies LIKE ?)";
        $params[] = "%{$_GET['term']}%";
        $params[] = "%{$_GET['term']}%";
        $params[] = "%{$_GET['term']}%";
    }
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $profiles = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if ($profiles) {
        foreach ($profiles as $profile) {
            $safeId = (int) $profile['id'];
            $displayName = htmlspecialchars($profile['name']);
            $shortName = mb_strlen($profile['name']) > 28 ? mb_substr($profile['name'], 0, 25) . '…' : $profile['name'];
            $shortName = htmlspecialchars($shortName);
            $initial = strtoupper(mb_substr(trim($profile['name']), 0, 1)) ?: '?';
            echo '<a href="profile.php?id=' . $safeId . '" class="block mb-3 p-3 card-soft hover:border-pink-500/40 flex items-center gap-3 transition-all">';
            if (!empty($profile['avatar'])) {
                echo '<img src="' . htmlspecialchars($profile['avatar']) . '" alt="" class="w-11 h-11 rounded-full object-cover flex-shrink-0 ring-2 ring-white/10">';
            } else {
                echo '<span class="avatar-initials flex-shrink-0">' . htmlspecialchars($initial) . '</span>';
            }
            echo '<div class="min-w-0 flex-1">';
            echo '<div class="font-semibold match-name text-pink-100" title="' . $displayName . '">' . $shortName . '</div>';
            if (!empty($profile['song'])) {
                echo '<div class="text-xs text-[var(--text-muted)] mt-0.5">';
                echo $profile['song_type'] === 'spotify' ? 'Listening on Spotify' : htmlspecialchars(mb_strlen($profile['song']) > 40 ? mb_substr($profile['song'], 0, 37) . '…' : $profile['song']);
                echo '</div>';
            }
            echo '</div>';
            echo '</a>';
        }
    } else {
        echo '<p class="text-[var(--text-muted)] text-sm">No matches yet — keep looking, your person is out there! <span class="heart">♥</span></p>';
    }
    ?>
      </div>
    </details>
  </div>

  <script>
    (function() {
      var wall = document.getElementById('wall-scroll');
      if (wall) wall.scrollTop = wall.scrollHeight;

      function setDetailsOpen() {
        var open = window.matchMedia('(min-width: 768px)').matches;
        var p = document.getElementById('details-player');
        var f = document.getElementById('details-find');
        if (p) p.open = open;
        if (f) f.open = open;
      }
      setDetailsOpen();
      window.addEventListener('resize', setDetailsOpen);
    })();
  </script>
</body>
</html>