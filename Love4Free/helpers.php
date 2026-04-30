<?php
/**
 * Generate a unique, cute/silly display name for auto-created guest profiles.
 * No suffix — just First_Second (e.g. Sweet_Potato). Uses large word lists; retries on collision.
 */
function generate_guest_name(PDO $pdo) {
    // First word: romantic + silly adjectives
    $first = [
        'Sweet', 'Gentle', 'Secret', 'Moon', 'Starry', 'Velvet', 'Honey', 'Tender', 'Soft', 'Blush', 'Twilight', 'Misty', 'Sugar', 'Warm', 'Cozy', 'Kind', 'True', 'Brave', 'Lucky', 'Happy', 'Curious', 'Bright', 'Calm', 'Bold', 'Wise', 'Silent', 'First', 'Pink', 'Candlelit',
        'Chaotic', 'Daring', 'Mysterious', 'Silly', 'Goofy', 'Cheeky', 'Fluffy', 'Bouncy', 'Zany', 'Wobbly', 'Snuggly', 'Giggly', 'Dizzy', 'Bubbly', 'Squishy', 'Fuzzy', 'Sassy', 'Peppy', 'Nerdy', 'Clumsy', 'Sleepy', 'Grumpy', 'Sneaky', 'Chunky', 'Tiny', 'Cosy', 'Toasty', 'Salty', 'Spicy', 'Zesty', 'Tangy', 'Crispy', 'Melty', 'Sticky',
    ];

    // Second word: romantic + silly nouns
    $second = [
        'Sunflower', 'Starlight', 'Moonbeam', 'Heart', 'Soul', 'Dreamer', 'Kiss', 'Serenade', 'Admirer', 'Embrace', 'Wish', 'Spark', 'Rose', 'Dream', 'Promise', 'Sky', 'Meadow', 'Butterfly', 'Lotus', 'Horizon', 'Sparrow', 'Phoenix', 'River', 'Comet', 'Wanderer', 'Plum', 'Marshmallow', 'Cupcake', 'Muffin', 'Bean',
        'Potato', 'Penguin', 'Nugget', 'Peanut', 'Pumpkin', 'Pickle', 'Waffle', 'Pudding', 'Biscuit', 'Tater', 'Mochi', 'Noodle', 'Taco', 'Bagel', 'Donut', 'Pretzel', 'Omelette', 'Croissant', 'Sourdough', 'Avocado', 'Broccoli', 'Radish', 'Turnip', 'Parsnip', 'Kumquat', 'Rutabaga', 'Cabbage', 'Artichoke',
        'Flamingo', 'Capybara', 'Axolotl', 'Platypus', 'Manatee', 'Narwhal', 'Otter', 'Sloth', 'Ferret', 'Hedgehog', 'Raccoon', 'Possum', 'Armadillo', 'Meerkat', 'Quokka', 'Tapir', 'Pangolin', 'Llama', 'Alpaca', 'Walrus', 'Seal', 'Koala', 'Panda', 'Kiwi', 'Pelican', 'Puffin', 'Duckling',
        'Sock', 'Mitten', 'Blanket', 'Pillow', 'Slipper', 'Teapot', 'Mug', 'Kettle', 'Toaster', 'WaffleIron', 'Spatula', 'Ladle', 'Doorknob', 'Cushion', 'Rug', 'Curtain', 'Napkin', 'Apron', 'Scarf', 'Beanie', 'Bubble', 'Confetti', 'Glitter', 'Sprinkle', 'Doodle', 'Scribble', 'Wiggle', 'Boop', 'Blop', 'Plop',
    ];

    $maxAttempts = 50;
    for ($i = 0; $i < $maxAttempts; $i++) {
        $name = $first[array_rand($first)] . '_' . $second[array_rand($second)];
        $stmt = $pdo->prepare("SELECT id FROM profiles WHERE name = ?");
        $stmt->execute([$name]);
        if ($stmt->fetch() === false) {
            return $name;
        }
    }
    return 'Guest_' . substr(uniqid(), -6);
}

/**
 * Normalize a YouTube URL to embed form. Supports watch, shorts, youtu.be.
 * Returns embed URL or original string if not YouTube.
 */
function youtube_to_embed($url) {
    $url = trim($url);
    if (empty($url)) return '';
    // watch?v=ID
    if (preg_match('/youtube\.com\/watch\?v=([a-zA-Z0-9_-]{11})/i', $url, $m)) return 'https://www.youtube.com/embed/' . $m[1];
    // shorts/ID
    if (preg_match('/youtube\.com\/shorts\/([a-zA-Z0-9_-]{11})/i', $url, $m)) return 'https://www.youtube.com/embed/' . $m[1];
    // youtu.be/ID
    if (preg_match('/youtu\.be\/([a-zA-Z0-9_-]{11})/i', $url, $m)) return 'https://www.youtube.com/embed/' . $m[1];
    // already embed
    if (preg_match('/youtube\.com\/embed\/([a-zA-Z0-9_-]{11})/i', $url, $m)) return 'https://www.youtube.com/embed/' . $m[1];
    return $url;
}

/**
 * Extract all YouTube video IDs from a string. Returns array of 11-char IDs.
 */
function youtube_extract_ids($text) {
    $ids = [];
    if (preg_match_all('/(?:youtube\.com\/watch\?v=|youtube\.com\/shorts\/|youtu\.be\/|youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/i', $text, $m)) {
        foreach ($m[1] as $id) {
            if (!in_array($id, $ids)) $ids[] = $id;
        }
    }
    return $ids;
}

/**
 * Strip YouTube URLs from text (so we don't show raw URL when we show embed).
 */
function youtube_strip_from_text($text) {
    return preg_replace('/\s*https?:\/\/(?:www\.)?(?:youtube\.com\/(?:watch\?v=|shorts\/)|youtu\.be\/)[a-zA-Z0-9_-]+\S*/i', '', $text);
}

/**
 * Strip Spotify URLs from text.
 */
function spotify_strip_from_text($text) {
    return preg_replace('/\s*https?:\/\/(?:open\.)?spotify\.com\/(?:track|album|playlist)\/[a-zA-Z0-9]+\S*/i', '', $text);
}

/**
 * Extract Spotify track/album/playlist links from text. Returns array of ['type' => 'track'|'album'|'playlist', 'id' => id].
 */
function spotify_extract_embeds($text) {
    $embeds = [];
    if (preg_match_all('/https?:\/\/(?:open\.)?spotify\.com\/(track|album|playlist)\/([a-zA-Z0-9]+)/i', $text, $m, PREG_SET_ORDER)) {
        foreach ($m as $match) {
            $type = strtolower($match[1]);
            $id = $match[2];
            $key = $type . ':' . $id;
            if (!isset($embeds[$key])) {
                $embeds[$key] = ['type' => $type, 'id' => $id];
            }
        }
    }
    return array_values($embeds);
}
