/* ===================================================================
   PASSANALYTIQ PASSWORD GENERATOR - Core + UI Integration
   Random modes use crypto-secure RNG; Memory Seed mode is deterministic.
   =================================================================== */

// ===== EFF-STYLE SHORT WORDLIST (1344 words, ~10.39 bits per word) =====
const EFF_SHORT_WORDLIST = [
    "acid", "acme", "acre", "acts", "aged", "also", "arch", "area", "army", "away",
    "back", "bail", "bait", "bake", "ball", "band", "bank", "barn", "base", "bash",
    "bath", "bead", "beam", "bean", "bear", "beat", "beef", "been", "beer", "bell",
    "belt", "bend", "bent", "best", "bias", "bike", "bill", "bind", "bird", "bite",
    "blog", "blow", "blue", "blur", "boar", "boat", "body", "bold", "bolt", "bomb",
    "bond", "bone", "book", "boot", "born", "boss", "both", "bowl", "bred", "brew",
    "bulk", "bull", "burn", "bury", "bush", "bust", "busy", "buzz", "cafe", "cage",
    "cake", "calf", "call", "calm", "came", "camp", "cape", "card", "care", "carp",
    "cart", "case", "cash", "cast", "cave", "cell", "chat", "chef", "chin", "chip",
    "chop", "cite", "city", "clad", "clam", "clap", "claw", "clay", "clip", "clock",
    "clone", "club", "clue", "coal", "coat", "code", "coil", "coin", "cold", "colt",
    "comb", "come", "cone", "cook", "cool", "cope", "copy", "cord", "core", "cork",
    "corn", "cost", "cosy", "coup", "cove", "crab", "crew", "crop", "crow", "cube",
    "cult", "cure", "curl", "cute", "cycle", "dale", "dame", "lamp", "damp", "dare",
    "dark", "darn", "dart", "dash", "data", "date", "dawn", "dead", "deaf", "deal",
    "dean", "dear", "debt", "deck", "deed", "deem", "deep", "deer", "demo", "dent",
    "deny", "desk", "dial", "dice", "diet", "dine", "dint", "dire", "dirt", "disc",
    "dish", "disk", "dock", "does", "dole", "dome", "done", "doom", "door", "dose",
    "dove", "down", "doze", "drab", "drag", "draw", "drip", "drop", "drug", "drum",
    "dual", "duck", "dude", "duel", "duet", "duke", "dull", "duly", "dump", "dune",
    "dung", "dunk", "dusk", "dust", "duty", "dyer", "each", "earl", "earn", "ease",
    "east", "easy", "edge", "edgy", "edit", "else", "emit", "ends", "epic", "even",
    "ever", "exam", "exec", "exil", "exit", "expo", "face", "fact", "fade", "fail",
    "fair", "fake", "fall", "fame", "fang", "fare", "farm", "fast", "fate", "fawn",
    "fear", "feat", "feed", "feel", "fell", "felt", "fern", "file", "fill", "film",
    "find", "fine", "fire", "firm", "fish", "fist", "five", "flag", "flak", "flan",
    "flap", "flat", "flaw", "flea", "fled", "flew", "flex", "flip", "flit", "flog",
    "flop", "flow", "flue", "flux", "foam", "foci", "foil", "fold", "folk", "fond",
    "font", "food", "fool", "foot", "ford", "fore", "fork", "form", "fort", "foul",
    "four", "fowl", "fray", "free", "frog", "from", "fuel", "full", "fume", "fund",
    "funk", "furl", "fury", "fuse", "fuss", "fuzz", "gain", "gait", "gale", "gall",
    "game", "gang", "gape", "garb", "gash", "gasp", "gate", "gave", "gaze", "gear",
    "gene", "germ", "gift", "gild", "gilt", "gist", "give", "glad", "glee", "glen",
    "glib", "glob", "glom", "glow", "glue", "glum", "glut", "gnat", "gnaw", "goad",
    "goat", "goes", "gold", "golf", "gone", "good", "gore", "grab", "gram", "gray",
    "grew", "grid", "grim", "grin", "grip", "grit", "grow", "grub", "gulf", "gull",
    "gulp", "gum", "gunk", "gust", "guts", "guru", "gust", "hack", "hail", "hair",
    "hale", "half", "hall", "halt", "hand", "hang", "hare", "hark", "harm", "harp",
    "hash", "hast", "hate", "haul", "have", "hawk", "haze", "hazy", "head", "heal",
    "heap", "hear", "heat", "heed", "heel", "held", "hell", "helm", "help", "hemp",
    "herb", "herd", "here", "hero", "hers", "hike", "hill", "hilt", "hind", "hint",
    "hire", "hiss", "hive", "hoax", "hock", "hold", "hole", "holy", "home", "hone",
    "hood", "hook", "hoop", "hope", "horn", "hose", "host", "hour", "howl", "hubs",
    "hued", "hues", "huge", "hull", "hump", "hung", "hunk", "hunt", "hurl", "hurt",
    "hush", "hymn", "hype", "iced", "icon", "idea", "idle", "idly", "iffy", "inch",
    "into", "iron", "isle", "item", "jabs", "jack", "jade", "jail", "jamb", "jams",
    "jape", "jars", "java", "jaws", "jays", "jazz", "jean", "jeep", "jeer", "jell",
    "jerk", "jest", "jets", "jibe", "jigs", "jilt", "jinx", "jive", "jobs", "jock",
    "jogs", "join", "joke", "jolt", "jots", "jury", "just", "jute", "keen", "keep",
    "kelp", "kept", "keys", "kick", "kids", "kill", "kilt", "kind", "king", "kiss",
    "kite", "knack", "knee", "knew", "knit", "knob", "knot", "know", "lace", "lack",
    "lacy", "laid", "lake", "lame", "lamp", "land", "lane", "lard", "lark", "lash",
    "lass", "last", "late", "laud", "lawn", "laws", "lazy", "lead", "leaf", "leak",
    "lean", "leap", "left", "lend", "lens", "lent", "less", "levy", "liar", "lice",
    "lick", "lied", "lieu", "life", "lift", "like", "lily", "limb", "lime", "limp",
    "line", "link", "lint", "lion", "lips", "list", "live", "load", "loaf", "loam",
    "loan", "lobe", "lock", "lode", "loft", "loge", "logo", "lone", "long", "look",
    "loom", "loop", "loot", "lord", "lore", "lose", "loss", "lost", "lots", "loud",
    "love", "luck", "luge", "lull", "lump", "lure", "lurk", "lush", "lust", "lynx",
    "lyre", "mace", "made", "maid", "mail", "main", "make", "male", "mall", "malt",
    "mane", "many", "maps", "mare", "mark", "mars", "mart", "mash", "mask", "mass",
    "mast", "mate", "math", "maze", "mead", "meal", "mean", "meat", "meek", "meet",
    "meld", "melt", "memo", "mend", "menu", "mere", "mesh", "mess", "mica", "mice",
    "mild", "mile", "milk", "mill", "mime", "mind", "mine", "mint", "mire", "mirk",
    "miss", "mist", "mite", "mitt", "moan", "moat", "mock", "mode", "mold", "mole",
    "molt", "monk", "mood", "moon", "moor", "more", "morn", "moss", "most", "moth",
    "move", "much", "muck", "muff", "mule", "mull", "mumm", "mung", "murk", "muse",
    "mush", "musk", "must", "mute", "myth", "nabs", "nags", "nail", "name", "nape",
    "naps", "navy", "near", "neat", "neck", "need", "nest", "nets", "news", "next",
    "nice", "nick", "nine", "node", "nods", "none", "nook", "noon", "norm", "nose",
    "note", "noun", "numb", "nuts", "oafs", "oaks", "oars", "oath", "obey", "odds",
    "odor", "omen", "omit", "once", "ones", "only", "onto", "opal", "open", "opts",
    "oral", "orbs", "orca", "ores", "oust", "outs", "oven", "over", "owed", "owes",
    "owls", "owns", "pace", "pack", "pact", "page", "paid", "pail", "pain", "pair",
    "pale", "palm", "pane", "pang", "pans", "pant", "park", "part", "pass", "past",
    "path", "pave", "pawn", "pays", "peak", "peal", "pear", "peas", "peat", "peck",
    "peel", "peep", "peer", "pelt", "pend", "pens", "pent", "peon", "perk", "perm",
    "pert", "pest", "pets", "pick", "pier", "pike", "pile", "pill", "pine", "pink",
    "pins", "pint", "pipe", "pits", "pity", "plan", "play", "plea", "plod", "plot",
    "plow", "ploy", "plug", "plum", "plus", "pock", "pods", "poem", "poet", "poke",
    "pole", "poll", "polo", "pomp", "pond", "pony", "pool", "poor", "pope", "pops",
    "pore", "pork", "port", "pose", "posh", "post", "pour", "pray", "prep", "prey",
    "prim", "prod", "prop", "prow", "prys", "pubs", "puck", "puff", "pugs", "pull",
    "pulp", "pump", "puns", "punk", "pups", "pure", "purr", "push", "puts", "putt",
    "quad", "quay", "quip", "quit", "quiz", "race", "rack", "raft", "rage", "rags",
    "raid", "rail", "rain", "rake", "ramp", "rams", "rang", "rank", "rant", "raps",
    "rash", "rasp", "rate", "rave", "rays", "raze", "read", "real", "ream", "reap",
    "rear", "reed", "reef", "reel", "rein", "rely", "rend", "rent", "rest", "rice",
    "rich", "ride", "rift", "rigs", "rile", "rill", "rime", "rind", "ring", "riot",
    "ripe", "rise", "risk", "road", "roam", "roar", "robe", "rock", "rode", "role",
    "roll", "romp", "roof", "rook", "room", "root", "rope", "rose", "rosy", "rote",
    "rout", "rove", "rows", "rubs", "ruby", "rude", "rued", "rues", "ruff", "rugs",
    "ruin", "rule", "rump", "rune", "rung", "runs", "runt", "ruse", "rush", "rust",
    "ruts", "sack", "safe", "sage", "said", "sail", "sake", "sale", "salt", "same",
    "sand", "sane", "sang", "sank", "sari", "sash", "save", "saws", "says", "scab",
    "scam", "scan", "scar", "seal", "seam", "sear", "seas", "seat", "sect", "seed",
    "seek", "seem", "seen", "self", "sell", "semi", "send", "sent", "sept", "sewn",
    "shed", "shim", "shin", "ship", "shod", "shoo", "shop", "shot", "show", "shut",
    "sick", "side", "sift", "sigh", "sign", "silk", "sill", "silo", "silt", "sine",
    "sing", "sink", "sips", "sire", "site", "sits", "size", "skat", "skid", "skim",
    "skin", "skip", "skit", "slab", "slag", "slam", "slap", "slat", "slaw", "slay",
    "sled", "slew", "slid", "slim", "slit", "slob", "sloe", "slog", "slop", "slot",
    "slow", "slug", "slum", "slur", "smog", "snap", "snip", "snit", "snob", "snot",
    "snow", "snub", "snug", "soak", "soap", "soar", "sock", "soda", "sofa", "soft",
    "soil", "sold", "sole", "solo", "some", "song", "soon", "soot", "sore", "sort",
    "soul", "sour", "span", "spar", "spec", "sped", "spin", "spit", "spot", "spry",
    "spud", "spun", "spur", "stab", "stag", "star", "stay", "stem", "step", "stew",
    "stir", "stop", "stub", "stud", "stun", "such", "suck", "sued", "suet", "suit",
    "sulk", "sumo", "sums", "sung", "sunk", "sure", "surf", "swan", "swap", "sway",
    "swim", "swum", "sync", "tabs", "tack", "tact", "tags", "tail", "take", "tale",
    "talk", "tall", "tame", "tamp", "tang", "tank", "tape", "taps", "tarn", "tarp",
    "tart", "task", "taxi", "teak", "teal", "team", "tear", "teen", "tell", "temp",
    "tend", "tens", "tent", "term", "tern", "test", "text", "than", "that", "thaw",
    "them", "then", "they", "thin", "this", "thud", "thug", "thus", "tick", "tide",
    "tidy", "tied", "tier", "ties", "tiff", "tile", "till", "tilt", "time", "tine",
    "tint", "tiny", "tips", "tire", "toad", "toes", "tofu", "toga", "toil", "told",
    "toll", "tomb", "tome", "tone", "tons", "took", "tool", "tops", "tore", "torn",
    "tort", "toss", "tour", "tout", "town", "toys", "trap", "tray", "tree", "trek",
    "trim", "trio", "trip", "trod", "trot", "true", "tsar", "tube", "tubs", "tuck",
    "tuft", "tugs", "tulip", "tuna", "tune", "turf", "turn", "tusk", "tutu", "twig",
    "twin", "type", "ugly", "undo", "unit", "unto", "upon", "urge", "user", "vain",
    "vale", "vane", "vary", "vase", "vast", "vats", "veal", "veer", "vent", "verb",
    "very", "vest", "veto", "vial", "vibe", "vice", "vied", "vies", "view", "vine",
    "visa", "void", "volt", "vote", "vows", "wade", "wage", "wail", "wait", "wake",
    "walk", "wall", "wand", "wane", "want", "ward", "warm", "warn", "warp", "wars",
    "wart", "wary", "wash", "wasp", "wave", "wavy", "waxy", "ways", "weak", "wean",
    "wear", "weed", "week", "weft", "weld", "well", "welt", "went", "wept", "were",
    "west", "what", "when", "whet", "whim", "whip", "whom", "wick", "wide", "wife",
    "wigs", "wild", "will", "wilt", "wily", "wimp", "wind", "wine", "wing", "wink",
    "wins", "wipe", "wire", "wise", "wish", "wisp", "with", "wits", "woke", "wolf",
    "womb", "wont", "wood", "woof", "wool", "word", "wore", "work", "worm", "worn",
    "wove", "wrap", "wren", "writ", "yack", "yaks", "yams", "yank", "yaps", "yard",
    "yarn", "yawl", "yawn", "yawp", "year", "yell", "yelp", "yoga", "yoke", "yore",
    "your", "yowl", "yurt", "zany", "zaps", "zeal", "zero", "zest", "zinc", "zine",
    "zing", "zone", "zoom", "zoos"
];

// ===== GENERATOR CORE (Pure, testable logic) =====
const GeneratorCore = {

    /** Cryptographically secure random integer in [0, max) */
    secureRandomInt(max) {
        // Guard: max must be a positive integer > 1 for rejection sampling
        // to work. When max <= 0 or max === 1, the only valid result is 0.
        // Without this guard, max === 1 causes limit === 0x100000000 which
        // makes almost every sample retry, risking stack overflow.
        if (!Number.isFinite(max) || max <= 1) return 0;
        max = Math.floor(max); // ensure integer

        const array = new Uint32Array(1);
        const cryptoObj = (typeof window !== 'undefined' && window.crypto) || (typeof crypto !== 'undefined' ? crypto : null);
        if (cryptoObj && cryptoObj.getRandomValues) {
            cryptoObj.getRandomValues(array);
        } else {
            // Fallback for Node.js test environment
            const nodeCrypto = require('crypto');
            array[0] = nodeCrypto.randomBytes(4).readUInt32BE(0);
        }
        // Rejection sampling to avoid modulo bias
        const limit = Math.floor(0x100000000 / max) * max;
        if (array[0] >= limit) {
            return GeneratorCore.secureRandomInt(max); // retry
        }
        return array[0] % max;
    },

    /** Fisher-Yates shuffle with crypto RNG (in-place, returns same array) */
    secureShuffle(arr) {
        for (let i = arr.length - 1; i > 0; i--) {
            const j = GeneratorCore.secureRandomInt(i + 1);
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    },

    /** Character pools */
    CHARSETS: {
        upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lower: 'abcdefghijklmnopqrstuvwxyz',
        numbers: '0123456789',
        symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
    },

    COMMON_RISKY_WORDS: new Set([
        'password', 'pass', 'admin', 'qwerty', 'welcome', 'login', 'user', 'test',
        'guest', 'root', 'secret', 'letmein', 'abc', '123', 'love',
    ]),

    WEAK_SEED_WORDS: new Set([
        'password', 'pass', 'admin', 'qwerty', 'welcome', 'login', 'user', 'test',
        'guest', 'root', 'secret', 'letmein', 'abc', '123', 'love', 'apple',
        'facebook', 'gmail', 'google', 'name', 'email', 'mail', 'account',
        'default', 'master', 'changeme', 'hello', 'computer', 'internet',
        'school', 'student', 'family', 'birthday', 'birthdate', 'company',
        'work', 'home', 'secretword', 'seed', 'passcode',
    ]),

    /**
     * Generate a random character password using "Guarantee and Shuffle".
     * @param {number} length - desired length (8–128)
     * @param {{upper:boolean, lower:boolean, numbers:boolean, symbols:boolean}} options
     * @returns {string}
     */
    generateCharPassword(length, options) {
        // Build list of enabled charsets
        const enabledSets = [];
        if (options.upper) enabledSets.push(GeneratorCore.CHARSETS.upper);
        if (options.lower) enabledSets.push(GeneratorCore.CHARSETS.lower);
        if (options.numbers) enabledSets.push(GeneratorCore.CHARSETS.numbers);
        if (options.symbols) enabledSets.push(GeneratorCore.CHARSETS.symbols);

        // Fallback: if nothing enabled, default to lowercase
        if (enabledSets.length === 0) {
            enabledSets.push(GeneratorCore.CHARSETS.lower);
        }

        // Ensure length >= number of enabled sets
        const effectiveLength = Math.max(length, enabledSets.length);

        // 1. Guarantee: pick one char from each enabled set
        const chars = [];
        for (const set of enabledSets) {
            chars.push(set[GeneratorCore.secureRandomInt(set.length)]);
        }

        // 2. Build combined pool
        const pool = enabledSets.join('');

        // 3. Fill remaining slots from combined pool
        for (let i = chars.length; i < effectiveLength; i++) {
            chars.push(pool[GeneratorCore.secureRandomInt(pool.length)]);
        }

        // 4. Crypto-shuffle entire array
        GeneratorCore.secureShuffle(chars);

        return chars.join('');
    },

    /**
     * Generate a passphrase from the bundled short wordlist.
     * @param {number} wordCount - number of words (3–12)
     * @param {string} separator - separator between words
     * @returns {string}
     */
    generatePassphrase(wordCount, separator) {
        const words = [];
        const list = EFF_SHORT_WORDLIST;
        for (let i = 0; i < wordCount; i++) {
            words.push(list[GeneratorCore.secureRandomInt(list.length)]);
        }
        return words.join(separator);
    },

    /**
     * Transform a memory word into a stronger, readable anchor.
     * The output is still recognizable, but it mixes controlled substitutions
     * such as Bat -> 8@t or Blue -> Blu3.
     * @param {string} raw
     * @returns {string}
     */
    transformMemoryWord(raw) {
        const word = GeneratorCore.sanitizeCustomWord(raw);
        if (!word) return '';

        let output = word.charAt(0).toUpperCase() + word.slice(1);

        const substitutionMap = {
            a: ['@', '4'],
            b: ['8'],
            e: ['3'],
            g: ['9'],
            i: ['1', '!'],
            o: ['0'],
            s: ['$'],
            t: ['7'],
            z: ['2'],
        };
        const candidates = [];
        Array.from(output).forEach((char, index) => {
            if (substitutionMap[char.toLowerCase()]) candidates.push(index);
        });
        if (candidates.length > 0) {
            const chars = Array.from(output);
            const maxSubstitutions = Math.min(candidates.length, word.length <= 3 ? 2 : 3);
            const minSubstitutions = Math.min(maxSubstitutions, word.length <= 4 ? 1 : 2);
            const count = minSubstitutions + GeneratorCore.secureRandomInt(maxSubstitutions - minSubstitutions + 1);
            const indexes = GeneratorCore.secureShuffle([...candidates]).slice(0, count);
            indexes.forEach(index => {
                const replacements = substitutionMap[chars[index].toLowerCase()];
                chars[index] = replacements[GeneratorCore.secureRandomInt(replacements.length)];
            });
            output = chars.join('');
        }

        if (Array.from(output).length >= 6 && GeneratorCore.secureRandomInt(5) === 0) {
            const chars = Array.from(output);
            const middle = Math.floor(chars.length / 2);
            const insertAt = Math.min(chars.length - 2, Math.max(2, middle + GeneratorCore.secureRandomInt(3) - 1));
            chars.splice(insertAt, 0, '-');
            output = chars.join('');
        }

        return output;
    },

    createWordVariant(raw, variantLevel = 0) {
        const word = GeneratorCore.sanitizeCustomWord(raw);
        if (!word) return '';
        const base = variantLevel % 2 === 0
            ? word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
            : word.toLowerCase();
        let variant = GeneratorCore.transformMemoryWord(base);
        if (variantLevel >= 1 && !/[0-9]/.test(variant)) {
            variant = `${variant}${GeneratorCore.randomDigit()}`;
        }
        if (variantLevel >= 2 && !/[!@#$%&?]/.test(variant)) {
            const chars = Array.from(variant);
            const insertAt = Math.max(1, Math.floor(chars.length / 2));
            chars.splice(insertAt, 0, GeneratorCore.randomReadableSymbol());
            variant = chars.join('');
        }
        return variant;
    },

    wrapAnchor(anchor, index) {
        const wrappers = [
            ['[', ']'],
            ['{', '}'],
            ['(', ')'],
        ];
        const wrapper = wrappers[index % wrappers.length];
        return `${wrapper[0]}${anchor}${wrapper[1]}`;
    },

    toTitleWord(raw) {
        const word = String(raw || '').toLowerCase();
        return word.charAt(0).toUpperCase() + word.slice(1);
    },

    getSecretWordPool() {
        return EFF_SHORT_WORDLIST.filter(word => (
            word.length >= 4
            && word.length <= 6
            && !GeneratorCore.COMMON_RISKY_WORDS.has(word)
        ));
    },

    randomSecretWord() {
        const pool = GeneratorCore.getSecretWordPool();
        return GeneratorCore.toTitleWord(pool[GeneratorCore.secureRandomInt(pool.length)]);
    },

    randomDigit() {
        return GeneratorCore.CHARSETS.numbers[GeneratorCore.secureRandomInt(10)];
    },

    randomReadableSymbol() {
        const symbols = '!@#$%&?';
        return symbols[GeneratorCore.secureRandomInt(symbols.length)];
    },

    generateSecretMiniChunk() {
        return `${GeneratorCore.randomSecretWord()}${GeneratorCore.randomDigit()}`;
    },

    /**
     * Generate a crypto-random but human-memorable hardening chunk.
     * It uses random short code words, digits, and one symbol instead of
     * unreadable random character soup.
     * @param {number|string=} lengthOrMode - optional length or hardening mode
     * @param {string=} mode - optional hardening mode
     * @returns {string}
     */
    generateSecretChunk(lengthOrMode, mode = 'balanced') {
        let requestedLength = lengthOrMode;
        let normalizedMode = mode === 'stronger' ? 'stronger' : 'balanced';
        if (typeof lengthOrMode === 'string') {
            normalizedMode = lengthOrMode === 'stronger' ? 'stronger' : 'balanced';
            requestedLength = undefined;
        }

        const minLength = normalizedMode === 'stronger' ? 12 : 6;
        const defaultLength = normalizedMode === 'stronger' ? 14 : 7;
        const resolvedLength = Number.isFinite(requestedLength)
            ? Math.max(minLength, Math.floor(requestedLength))
            : defaultLength;

        const makeCandidate = () => {
            const unitCount = normalizedMode === 'stronger' || resolvedLength >= 13
                ? 2 + GeneratorCore.secureRandomInt(Math.max(1, Math.min(4, Math.ceil(resolvedLength / 9)) - 1))
                : 1;
            const separators = ['-', '.', '_'];
            const separator = separators[GeneratorCore.secureRandomInt(separators.length)];
            const units = [];
            for (let i = 0; i < unitCount; i++) {
                units.push(GeneratorCore.generateSecretMiniChunk());
            }
            return `${units.join(separator)}${GeneratorCore.randomReadableSymbol()}`;
        };

        let best = '';
        for (let i = 0; i < 320; i++) {
            const candidate = makeCandidate();
            if (candidate.length === resolvedLength) return candidate;
            if (candidate.length < resolvedLength && candidate.length > best.length) best = candidate;
            if (!best || Math.abs(candidate.length - resolvedLength) < Math.abs(best.length - resolvedLength)) {
                best = candidate;
            }
        }

        if (best.length < resolvedLength) {
            const symbol = best.slice(-1);
            let body = best.slice(0, -1);
            while (body.length + symbol.length < resolvedLength) {
                body += GeneratorCore.randomDigit();
            }
            return `${body}${symbol}`;
        }
        return best;
    },

    /**
     * Generate a personalized password from 1-4 user words.
     * The personalized mode has one smart style: words are transformed,
     * wrapped, separated, and expanded until the result is long enough.
     * @param {string[]} words
     * @returns {{password:string, words:string[], transformedWords:string[], secretChunk:string, randomChunk:string, mode:string, targetLength:null, warnings:string[]}}
     */
    generatePersonalizedPassword(words) {
        const mode = 'personalized';
        const warnings = [];
        const allSanitizedWords = (words || [])
            .map(word => GeneratorCore.sanitizeCustomWord(word))
            .filter(Boolean);
        const limitedWords = allSanitizedWords.slice(0, 4);
        if (allSanitizedWords.length > 4) warnings.push('Using first 4 words.');
        const riskyWords = limitedWords.filter(word => GeneratorCore.isCommonRiskyWord(word));
        riskyWords.forEach(word => {
            warnings.push(`"${word}": This word is too common. Choose a memory word that is meaningful to you but not public or obvious.`);
        });
        const sanitizedWords = limitedWords.filter(word => !GeneratorCore.isCommonRiskyWord(word));

        if (sanitizedWords.length === 0) {
            return {
                password: '',
                words: [],
                transformedWords: [],
                secretChunk: '',
                randomChunk: '',
                mode,
                targetLength: null,
                warnings,
            };
        }

        const transformedWords = sanitizedWords.map(word => GeneratorCore.transformMemoryWord(word));
        const password = GeneratorCore.buildPersonalizedLayout(sanitizedWords, transformedWords);

        return {
            password,
            words: sanitizedWords,
            transformedWords,
            secretChunk: '',
            randomChunk: '',
            mode,
            targetLength: null,
            warnings,
        };
    },

    buildPersonalizedLayout(rawWords, transformedWords) {
        const separators = ['#', '-', '_', '.', '!', '@'];
        const minLength = rawWords.length === 1 ? 18 : 16;
        const anchors = transformedWords.map((word, index) => (
            index % 2 === 0 ? GeneratorCore.wrapAnchor(word, index) : word
        ));

        let variantLevel = 1;
        while (anchors.join('#').length < minLength && variantLevel <= 5) {
            const sourceWord = rawWords[(variantLevel - 1) % rawWords.length];
            const variant = GeneratorCore.createWordVariant(sourceWord, variantLevel);
            anchors.push(GeneratorCore.wrapAnchor(variant, anchors.length));
            variantLevel++;
        }

        if (!anchors.some(anchor => /[!@#$%&?]/.test(anchor))) {
            const index = GeneratorCore.secureRandomInt(anchors.length);
            anchors[index] = `${anchors[index]}${GeneratorCore.randomReadableSymbol()}`;
        }
        if (!anchors.some(anchor => /[0-9]/.test(anchor))) {
            const index = GeneratorCore.secureRandomInt(anchors.length);
            anchors[index] = `${anchors[index]}${GeneratorCore.randomDigit()}`;
        }

        const layout = GeneratorCore.secureRandomInt(4);
        if (layout === 0) {
            return anchors.map((anchor, index) => (
                index === 0 ? anchor : `${separators[index % separators.length]}${anchor}`
            )).join('');
        }
        if (layout === 1) {
            return `${anchors.join(separators[GeneratorCore.secureRandomInt(4)])}${GeneratorCore.randomReadableSymbol()}`;
        }
        if (layout === 2) {
            return `${GeneratorCore.wrapAnchor(anchors[0], 2)}${separators[GeneratorCore.secureRandomInt(separators.length)]}${anchors.slice(1).join('#')}`;
        }
        return anchors.join(separators[GeneratorCore.secureRandomInt(separators.length)]);
    },

    isCommonRiskyWord(raw) {
        const word = GeneratorCore.sanitizeCustomWord(raw).toLowerCase();
        return GeneratorCore.COMMON_RISKY_WORDS.has(word);
    },

    normalizeSeedInput(raw) {
        return String(raw || '').trim().normalize('NFC');
    },

    normalizeAccountLabel(raw) {
        return String(raw || '').trim().normalize('NFC').toLowerCase();
    },

    isWeakSeedWord(raw) {
        const seedWord = GeneratorCore.normalizeSeedInput(raw).toLowerCase();
        return GeneratorCore.WEAK_SEED_WORDS.has(seedWord);
    },

    buildDeterministicCharset(charsets = {}) {
        const requested = {
            upper: charsets.upper !== false,
            lower: charsets.lower !== false,
            numbers: charsets.numbers !== false,
            symbols: charsets.symbols !== false,
        };
        let groups = [];
        if (requested.upper) groups.push(GeneratorCore.CHARSETS.upper);
        if (requested.lower) groups.push(GeneratorCore.CHARSETS.lower);
        if (requested.numbers) groups.push(GeneratorCore.CHARSETS.numbers);
        if (requested.symbols) groups.push(GeneratorCore.CHARSETS.symbols);
        if (groups.length === 0) {
            groups = [
                GeneratorCore.CHARSETS.upper,
                GeneratorCore.CHARSETS.lower,
                GeneratorCore.CHARSETS.numbers,
                GeneratorCore.CHARSETS.symbols,
            ];
        }
        return {
            groups,
            pool: groups.join(''),
            signature: [
                requested.upper ? 'U' : '',
                requested.lower ? 'L' : '',
                requested.numbers ? 'N' : '',
                requested.symbols ? 'S' : '',
            ].join('') || 'ULNS',
        };
    },

    async sha256Bytes(input) {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            const encoded = new TextEncoder().encode(input);
            const digest = await window.crypto.subtle.digest('SHA-256', encoded);
            return Array.from(new Uint8Array(digest));
        }

        if (typeof require !== 'undefined') {
            const nodeCrypto = require('crypto');
            return Array.from(nodeCrypto.createHash('sha256').update(input, 'utf8').digest());
        }

        throw new Error('SHA-256 support is not available.');
    },

    async deterministicByteStream(base, count) {
        const bytes = [];
        let block = 1;
        while (bytes.length < count) {
            bytes.push(...await GeneratorCore.sha256Bytes(`${base}|block=${block}`));
            block++;
        }
        return bytes.slice(0, count);
    },

    createByteReader(bytes) {
        let index = 0;
        return {
            nextInt(max) {
                if (!Number.isFinite(max) || max <= 1) return 0;
                const value = (
                    (bytes[index++ % bytes.length] << 24)
                    | (bytes[index++ % bytes.length] << 16)
                    | (bytes[index++ % bytes.length] << 8)
                    | bytes[index++ % bytes.length]
                ) >>> 0;
                return value % Math.floor(max);
            },
        };
    },

    deterministicShuffle(items, reader) {
        const output = [...items];
        for (let i = output.length - 1; i > 0; i--) {
            const j = reader.nextInt(i + 1);
            [output[i], output[j]] = [output[j], output[i]];
        }
        return output;
    },

    /**
     * Generate a deterministic password from a memory seed and account label.
     * The same normalized inputs always produce the same output.
     * @param {{seedWord:string, accountLabel?:string, length?:number, charsets?:{upper?:boolean, lower?:boolean, numbers?:boolean, symbols?:boolean}}} options
     * @returns {Promise<{password:string, warnings:string[], seedWord:string, accountLabel:string, length:number}>}
     */
    async generateMemorySeedPassword(options = {}) {
        const seedWord = GeneratorCore.normalizeSeedInput(options.seedWord);
        const accountLabel = GeneratorCore.normalizeAccountLabel(options.accountLabel);
        const length = Math.max(16, Math.min(128, Math.floor(Number(options.length) || 24)));
        const warnings = [];

        if (!seedWord) {
            return {
                password: '',
                warnings: [],
                seedWord,
                accountLabel,
                length,
            };
        }

        if (GeneratorCore.isWeakSeedWord(seedWord)) {
            warnings.push('Weak memory word. Choose something less obvious.');
        }

        const charset = GeneratorCore.buildDeterministicCharset(options.charsets);
        const effectiveLength = Math.max(length, charset.groups.length);
        const domainBase = `PassAnalytiq-MemorySeed-v1|${seedWord}|${accountLabel}`;
        const base = `${domainBase}|length=${effectiveLength}|charsets=${charset.signature}`;
        const bytes = await GeneratorCore.deterministicByteStream(base, effectiveLength * 8 + 64);
        const reader = GeneratorCore.createByteReader(bytes);
        const chars = [];

        charset.groups.forEach(group => {
            chars.push(group[reader.nextInt(group.length)]);
        });

        while (chars.length < effectiveLength) {
            chars.push(charset.pool[reader.nextInt(charset.pool.length)]);
        }

        return {
            password: GeneratorCore.deterministicShuffle(chars, reader).join(''),
            warnings,
            seedWord,
            accountLabel,
            length: effectiveLength,
        };
    },

    /** Get the bundled wordlist size for entropy calculations */
    getWordlistSize() {
        return EFF_SHORT_WORDLIST.length;
    },

    /**
     * Backward-compatible custom-word entry point.
     * The simplified product uses the smart personalized word transformer.
     */
    assembleCustomPassword(words) {
        return GeneratorCore.generatePersonalizedPassword(words).password;
    },

    /**
     * Sanitize a custom base word for personalized generation.
     * Removes non-printing controls, rejects HTML-like input, and truncates
     * to a maximum of 20 Unicode code points.
     * @param {string} raw - the raw user input
     * @returns {string} sanitized word, or empty string if invalid
     */
    sanitizeCustomWord(raw) {
        if (typeof raw !== 'string') return '';
        const MAX_WORD_LENGTH = 20;
        const cleaned = raw
            .replace(/[\u0000-\u001F\u007F-\u009F]/g, '')
            .trim();

        if (!cleaned || /[<>]/.test(cleaned)) return '';
        return Array.from(cleaned).slice(0, MAX_WORD_LENGTH).join('');
    },
};

// Expose for Node.js testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { GeneratorCore, EFF_SHORT_WORDLIST };
}

/* ===== UI INTEGRATION (browser-only) ===== */
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        if (!document.getElementById('generatedOutput')) return;

        const els = {
            modeRandomBtn: document.getElementById('modeRandomBtn'),
            modePersonalBtn: document.getElementById('modePersonalBtn'),
            modeSeedBtn: document.getElementById('modeSeedBtn'),
            randomPanel: document.getElementById('randomPanel'),
            personalPanel: document.getElementById('personalPanel'),
            memorySeedPanel: document.getElementById('memorySeedPanel'),
            randomLength: document.getElementById('randomLength'),
            randomLengthValue: document.getElementById('randomLengthValue'),
            chkUpper: document.getElementById('chkUpper'),
            chkLower: document.getElementById('chkLower'),
            chkNumbers: document.getElementById('chkNumbers'),
            chkSymbols: document.getElementById('chkSymbols'),
            customWordInput: document.getElementById('customWordInput'),
            addWordBtn: document.getElementById('addWordBtn'),
            wordTags: document.getElementById('wordTags'),
            wordWarning: document.getElementById('wordWarning'),
            seedWordInput: document.getElementById('seedWordInput'),
            accountLabelInput: document.getElementById('accountLabelInput'),
            seedLength: document.getElementById('seedLength'),
            seedLengthValue: document.getElementById('seedLengthValue'),
            seedWarning: document.getElementById('seedWarning'),
            generateBtn: document.getElementById('generateBtn'),
            generatedOutput: document.getElementById('generatedOutput'),
            copyBtn: document.getElementById('copyBtn'),
            strengthBadge: document.getElementById('strengthBadge'),
            strengthLabel: document.getElementById('strengthLabel'),
            scoreValue: document.getElementById('scoreValue'),
            lengthValue: document.getElementById('lengthValue'),
            weaknessCount: document.getElementById('weaknessCount'),
            personalNote: document.getElementById('personalNote'),
        };

        let mode = 'random';
        let customWords = [];
        let generateTimer = null;
        let generateRequestId = 0;

        function scheduleGenerate(delay = 150) {
            clearTimeout(generateTimer);
            generateTimer = setTimeout(generatePassword, delay);
        }

        function setMode(nextMode) {
            mode = nextMode;
            els.modeRandomBtn.classList.toggle('active', mode === 'random');
            els.modePersonalBtn.classList.toggle('active', mode === 'personal');
            els.modeSeedBtn.classList.toggle('active', mode === 'seed');
            els.modeRandomBtn.setAttribute('aria-selected', String(mode === 'random'));
            els.modePersonalBtn.setAttribute('aria-selected', String(mode === 'personal'));
            els.modeSeedBtn.setAttribute('aria-selected', String(mode === 'seed'));
            els.randomPanel.classList.toggle('active', mode === 'random');
            els.personalPanel.classList.toggle('active', mode === 'personal');
            els.memorySeedPanel.classList.toggle('active', mode === 'seed');
            document.body.classList.toggle('memory-seed-mode', mode === 'seed');
            if (mode === 'seed') {
                els.personalNote.textContent = 'Recreate the same password with the same memory word and website/app name.';
            } else if (mode === 'personal') {
                els.personalNote.textContent = 'Your words make it memorable. The structure makes it harder to guess.';
            } else {
                els.personalNote.textContent = 'Includes crypto-secure randomness.';
            }
            generatePassword();
        }

        function addCustomWord() {
            const rawWords = els.customWordInput.value
                .split(/[\s,]+/)
                .map(value => value.trim())
                .filter(Boolean);
            if (rawWords.length === 0) return;
            rawWords.forEach(raw => {
                const word = GeneratorCore.sanitizeCustomWord(raw);
                if (word && customWords.length < 4) customWords.push(word);
            });
            els.customWordInput.value = '';
            renderWords();
            scheduleGenerate(80);
        }

        function removeCustomWord(index) {
            customWords.splice(index, 1);
            renderWords();
            scheduleGenerate(80);
        }

        function renderWords() {
            const nodes = customWords.map((word, index) => {
                const tag = document.createElement('button');
                tag.type = 'button';
                tag.className = 'word-tag';
                tag.textContent = `${word} x`;
                tag.setAttribute('aria-label', `Remove ${word}`);
                tag.addEventListener('click', () => removeCustomWord(index));
                return tag;
            });
            els.wordTags.replaceChildren(...nodes);
        }

        function getRandomOptions() {
            return {
                upper: els.chkUpper.checked,
                lower: els.chkLower.checked,
                numbers: els.chkNumbers.checked,
                symbols: els.chkSymbols.checked,
            };
        }

        function renderAnalysis(password) {
            const result = typeof analyzePassword === 'function' ? analyzePassword(password) : null;
            if (!result) {
                els.strengthLabel.textContent = '-';
                els.strengthBadge.textContent = '-';
                els.scoreValue.textContent = '-';
                els.lengthValue.textContent = '-';
                els.weaknessCount.textContent = '-';
                return;
            }

            const weaknessCount = result.patterns.length + (result.length < 15 ? 1 : 0);
            els.strengthLabel.textContent = result.label;
            els.strengthBadge.textContent = result.label;
            els.strengthLabel.style.color = STRENGTH_COLORS[result.label] || '#8b949e';
            els.strengthBadge.style.color = STRENGTH_COLORS[result.label] || '#8b949e';
            els.strengthBadge.style.borderColor = STRENGTH_COLORS[result.label] || '#3a4a5d';
            els.scoreValue.textContent = `${result.score}/100`;
            els.lengthValue.textContent = String(result.length);
            els.weaknessCount.textContent = String(weaknessCount);
        }

        async function generatePassword() {
            const requestId = ++generateRequestId;
            let password = '';
            if (mode === 'random') {
                password = GeneratorCore.generateCharPassword(parseInt(els.randomLength.value, 10), getRandomOptions());
                els.wordWarning.textContent = '';
                els.seedWarning.textContent = '';
            } else if (mode === 'personal') {
                const generated = GeneratorCore.generatePersonalizedPassword(customWords);
                password = generated.password;
                els.wordWarning.textContent = generated.warnings.join(' ');
                els.seedWarning.textContent = '';
                if (!password) {
                    els.generatedOutput.textContent = generated.warnings.length > 0
                        ? 'Choose another memory word.'
                        : 'Add a word to personalize your password.';
                    els.generatedOutput.classList.add('is-placeholder');
                    renderAnalysis('');
                    return;
                }
            } else {
                els.wordWarning.textContent = '';
                const generated = await GeneratorCore.generateMemorySeedPassword({
                    seedWord: els.seedWordInput.value,
                    accountLabel: els.accountLabelInput.value,
                    length: parseInt(els.seedLength.value, 10),
                    charsets: {
                        upper: true,
                        lower: true,
                        numbers: true,
                        symbols: true,
                    },
                });
                if (requestId !== generateRequestId) return;
                password = generated.password;
                els.seedWarning.textContent = generated.warnings.join(' ');
                if (!password) {
                    els.generatedOutput.textContent = 'Enter a memory word.';
                    els.generatedOutput.classList.add('is-placeholder');
                    renderAnalysis('');
                    return;
                }
            }

            if (requestId !== generateRequestId) return;
            els.generatedOutput.textContent = password;
            els.generatedOutput.classList.remove('is-placeholder');
            renderAnalysis(password);
        }

        els.modeRandomBtn.addEventListener('click', () => setMode('random'));
        els.modePersonalBtn.addEventListener('click', () => setMode('personal'));
        els.modeSeedBtn.addEventListener('click', () => setMode('seed'));
        els.randomLength.addEventListener('input', () => {
            els.randomLengthValue.textContent = els.randomLength.value;
            scheduleGenerate();
        });
        els.seedLength.addEventListener('input', () => {
            els.seedLengthValue.textContent = `${els.seedLength.value} characters`;
            scheduleGenerate();
        });
        [els.seedWordInput, els.accountLabelInput].forEach(control => {
            control.addEventListener('input', () => scheduleGenerate());
        });
        [els.chkUpper, els.chkLower, els.chkNumbers, els.chkSymbols].forEach(control => {
            control.addEventListener('change', () => scheduleGenerate(80));
        });
        els.addWordBtn.addEventListener('click', addCustomWord);
        els.customWordInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ',') {
                event.preventDefault();
                addCustomWord();
            }
        });
        els.customWordInput.addEventListener('blur', addCustomWord);
        els.generateBtn.addEventListener('click', generatePassword);
        els.copyBtn.addEventListener('click', () => {
            const value = els.generatedOutput.textContent;
            if (!value || value === '-' || value.startsWith('Add ') || els.generatedOutput.classList.contains('is-placeholder')) return;
            navigator.clipboard.writeText(value).then(() => {
                els.copyBtn.textContent = 'Copied';
                setTimeout(() => {
                    els.copyBtn.textContent = 'Copy';
                }, 1200);
            });
        });

        generatePassword();
    });
}
