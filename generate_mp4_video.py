import os
import sys
import asyncio
import subprocess
from PIL import Image, ImageDraw, ImageFont
import imageio_ffmpeg

FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()

# Slide Specifications: (Title, Subtitle, Bullet Points / Stats, Narration Text)
SCENES = [
    {
        "tag": "CYBERSECURITY INNOVATION",
        "title": "PhishShield AI Enterprise",
        "subtitle": "AI-Based Phishing Detection & URL Risk Analysis Platform",
        "author": "Architected by Safiq Ansari & Team",
        "boxes": [
            ("99.2%", "Model Accuracy", "#38bdf8"),
            ("< 1 ms", "Inference Latency", "#34d399"),
            ("4 Layers", "Hybrid Engine", "#a855f7")
        ],
        "points": [
            "Real-time heuristic & machine learning cyber defense against phishing attacks.",
            "Detects zero-day credential harvesting, brand impersonation, and botnet domains.",
            "Integrated SOC incident reporting, analytics dashboard, and REST API."
        ],
        "narration": "Welcome to PhishShield AI Enterprise. An intelligent cybersecurity and URL risk analysis system architected by Safiq Ansari and team to detect next-generation phishing threats with ninety-nine point two percent accuracy."
    },
    {
        "tag": "THREAT LANDSCAPE",
        "title": "Modern Cyber Threats Evade Basic Filters",
        "subtitle": "Why Traditional Blacklisting Fails Against Sophisticated Attacks",
        "author": "Vector Analysis",
        "boxes": [
            ("Social Engineering", "Fake bank & urgent credential theft SMS", "#f43f5e"),
            ("Typosquatting", "Deceptive lookalike domains e.g. paypa1.com", "#fbbf24"),
            ("DGA Botnets", "Algorithmically generated fast-flux malware domains", "#c084fc")
        ],
        "points": [
            "Blacklists fail because attackers spawn thousands of dynamic domains daily.",
            "Lookalike Unicode and Levenshtein characters deceive human eyes.",
            "Unregistered DGA domains execute automated command-and-control operations."
        ],
        "narration": "Modern cyber attackers bypass static blacklists using social engineering, typosquatting lookalike domains, and algorithmic DGA botnets that generate thousands of transient malicious links daily."
    },
    {
        "tag": "CORE ARCHITECTURE",
        "title": "4-Tier Hybrid Forensic Pipeline",
        "subtitle": "Multi-Engine Risk Differentiation & Deep Telemetry",
        "author": "Defense Pipeline",
        "boxes": [
            ("NLP Machine Learning", "TF-IDF N-grams with Multinomial Naive Bayes", "#38bdf8"),
            ("Shannon DGA Engine", "H(X) = -sum P(x) log2 P(x) entropy analysis", "#34d399"),
            ("Levenshtein Heuristics", "Brand distance, raw IP, shortener check", "#fbbf24"),
            ("VirusTotal & AI", "70+ Antivirus engines with LLM reasoning", "#a855f7")
        ],
        "points": [
            "Instant multi-engine score differentiation across every URL.",
            "Consonant clustering and Shannon entropy catch unpronounceable botnet domains.",
            "Sub-millisecond static and dynamic feature extraction."
        ],
        "narration": "To combat this, PhishShield AI utilizes a four-tier hybrid forensic pipeline, combining Natural Language Processing, Shannon Entropy DGA analysis, Levenshtein distance brand protection, and global VirusTotal intelligence."
    },
    {
        "tag": "LIVE DETECTION SIMULATION",
        "title": "Real-Time Detection: DGA Botnet URL",
        "subtitle": "Target URL: http://jpqftymiuver.ru (Flagged in 0.8 ms)",
        "author": "Forensic Telemetry",
        "boxes": [
            ("95.0%", "Critical Threat Score", "#ef4444"),
            ("3.585", "Shannon Entropy (High)", "#38bdf8"),
            ("HTTP Insecure", "Credential Theft Protocol", "#fbbf24")
        ],
        "points": [
            "Shannon Entropy: 3.585 indicates severe randomized character distribution.",
            "Consonant Cluster: 7 consecutive consonants flagged as non-human language.",
            "Automated SOC Directive: Immediate block and DNS quarantine assigned."
        ],
        "narration": "In this live simulation, an active DGA botnet link is scanned. The system detects high Shannon entropy of three point five eight five and seven consecutive consonants, instantly assigning a ninety-five percent critical risk score."
    },
    {
        "tag": "SOC COMPLIANCE",
        "title": "Exportable Enterprise Forensic PDF Reports",
        "subtitle": "Audit-Ready Security Intelligence & Remediation Directives",
        "author": "Incident Reporting",
        "boxes": [
            ("Brand Watermark", "Official SOC Enterprise Logo & Headers", "#38bdf8"),
            ("Multi-Engine Table", "Categorized individual engine contribution", "#34d399"),
            ("Zero Overlap", "Precision ReportLab vector layout engine", "#a855f7")
        ],
        "points": [
            "Automated PDF export with full incident telemetry and audit timestamps.",
            "Explicit risk weightage breakdown for enterprise compliance and forensic audit.",
            "Actionable recommendations for network administrators and security engineers."
        ],
        "narration": "Security analysts can generate audit-ready PDF forensic reports with complete multi-engine score differentiation, enterprise branding, and clear remediation instructions for SOC response."
    },
    {
        "tag": "CONCLUSION",
        "title": "Enterprise-Ready Cyber Defense",
        "subtitle": "High Precision, Lightning Speed, and Modern UI",
        "author": "Safiq Ansari & Team",
        "boxes": [
            ("High Accuracy", "Tested on 10,000+ real-world URLs", "#34d399"),
            ("Apple UI", "Glassmorphism responsive interface", "#38bdf8"),
            ("Ready to Deploy", "Full Flask & REST API stack", "#a855f7")
        ],
        "points": [
            "Complete end-to-end phishing protection system.",
            "Designed for enterprise SOC teams, academic demonstration, and real-world deployment.",
            "Thank you for watching the PhishShield AI presentation."
        ],
        "narration": "With high precision, sub-millisecond latency, and an intuitive glassmorphic interface, PhishShield AI is ready for immediate deployment. Thank you for watching our presentation."
    }
]

def create_slide_image(scene_data, slide_index, total_slides, output_path):
    W, H = 1920, 1080
    img = Image.new('RGB', (W, H), color='#030712')
    draw = ImageDraw.Draw(img)

    # Draw ambient background gradients / grid
    grid_color = (30, 58, 138, 40)
    for x in range(0, W, 60):
        draw.line([(x, 0), (x, H)], fill=(15, 23, 42), width=1)
    for y in range(0, H, 60):
        draw.line([(0, y), (W, y)], fill=(15, 23, 42), width=1)

    # Ambient glows (rectangles with rounded corners or borders)
    draw.rounded_rectangle([60, 40, W-60, H-40], radius=24, fill=(15, 23, 42), outline=(51, 65, 85), width=2)
    
    # Top Navbar Bar inside slide
    draw.rounded_rectangle([90, 65, W-90, 135], radius=16, fill=(17, 24, 39), outline=(71, 85, 105), width=1)
    
    # Try loading fonts, fallback to default if not present
    try:
        font_tag = ImageFont.truetype("arialbd.ttf", 20)
        font_title = ImageFont.truetype("arialbd.ttf", 46)
        font_sub = ImageFont.truetype("arial.ttf", 24)
        font_box_val = ImageFont.truetype("arialbd.ttf", 34)
        font_box_lbl = ImageFont.truetype("arial.ttf", 18)
        font_body = ImageFont.truetype("arial.ttf", 22)
        font_nav = ImageFont.truetype("arialbd.ttf", 22)
        font_nav_small = ImageFont.truetype("arial.ttf", 16)
    except Exception:
        font_tag = font_title = font_sub = font_box_val = font_box_lbl = font_body = font_nav = font_nav_small = ImageFont.load_default()

    # Paste Logo if exists
    logo_path = 'static/logo.png'
    if os.path.exists(logo_path):
        try:
            logo = Image.open(logo_path).convert('RGBA')
            logo = logo.resize((50, 50), Image.Resampling.LANCZOS)
            img.paste(logo, (110, 75), logo)
        except Exception:
            pass

    # Header text
    draw.text((175, 78), "PhishShield AI Enterprise", fill="#38bdf8", font=font_nav)
    draw.text((175, 104), "Automated Cyber Threat & Risk Analysis System", fill="#94a3b8", font=font_nav_small)

    # Slide Number pill
    slide_text = f"Slide {slide_index + 1} of {total_slides}"
    draw.rounded_rectangle([W-270, 75, W-110, 125], radius=12, fill=(30, 41, 59), outline=(59, 130, 246), width=1)
    draw.text((W-250, 90), slide_text, fill="#f8fafc", font=font_nav_small)

    # Tag Badge
    tag_text = scene_data["tag"]
    draw.rounded_rectangle([110, 165, 110 + len(tag_text)*13 + 30, 205], radius=10, fill=(12, 74, 110), outline=(56, 189, 248), width=1)
    draw.text((125, 175), tag_text, fill="#38bdf8", font=font_tag)

    # Title & Subtitle
    draw.text((110, 220), scene_data["title"], fill="#ffffff", font=font_title)
    draw.text((110, 280), scene_data["subtitle"], fill="#94a3b8", font=font_sub)

    # Horizontal accent divider
    draw.line([(110, 325), (W-110, 325)], fill=(51, 65, 85), width=2)
    draw.line([(110, 325), (450, 325)], fill=(56, 189, 248), width=3)

    # Stat / Feature Highlight Boxes
    boxes = scene_data.get("boxes", [])
    num_boxes = len(boxes)
    if num_boxes > 0:
        box_width = (W - 220 - (num_boxes - 1) * 30) // num_boxes
        for i, (val, lbl, color) in enumerate(boxes):
            bx = 110 + i * (box_width + 30)
            by = 350
            bh = 170
            draw.rounded_rectangle([bx, by, bx + box_width, by + bh], radius=18, fill=(17, 24, 39), outline=(71, 85, 105), width=2)
            # Top accent bar on box
            draw.rounded_rectangle([bx, by, bx + box_width, by + 6], radius=3, fill=color)
            draw.text((bx + 25, by + 35), val, fill=color, font=font_box_val)
            
            # Multi-line handling for box labels
            words = lbl.split(' ')
            line1 = ' '.join(words[:4])
            line2 = ' '.join(words[4:]) if len(words) > 4 else ''
            draw.text((bx + 25, by + 90), line1, fill="#e2e8f0", font=font_box_lbl)
            if line2:
                draw.text((bx + 25, by + 120), line2, fill="#94a3b8", font=font_box_lbl)

    # Key Architectural / Forensic Points
    points = scene_data.get("points", [])
    py = 560
    draw.text((110, py), "KEY ARCHITECTURAL & FORENSIC CAPABILITIES:", fill="#38bdf8", font=font_tag)
    py += 45
    for pt in points:
        # Draw glowing bullet icon
        draw.ellipse([115, py + 6, 127, py + 18], fill=(56, 189, 248), outline=(255, 255, 255))
        draw.text((145, py), pt, fill="#cbd5e1", font=font_body)
        py += 48

    # Bottom Footer Bar
    draw.rounded_rectangle([90, H-120, W-90, H-60], radius=14, fill=(15, 23, 42), outline=(51, 65, 85), width=1)
    draw.text((120, H-98), "PhishShield AI Enterprise  |  Cyber Threat Intelligence Platform", fill="#64748b", font=font_nav_small)
    draw.text((W-420, H-98), "AI-Powered Threat Neutralization", fill="#38bdf8", font=font_nav_small)

    img.save(output_path, quality=95)
    print(f"[+] Slide {slide_index + 1} rendered to {output_path}")

async def generate_audio_for_scene(text, output_mp3_path):
    import edge_tts
    # High-quality Microsoft natural neural voice
    VOICE = "en-US-ChristopherNeural"
    communicate = edge_tts.Communicate(text, VOICE, rate="-4%", pitch="+0Hz")
    await communicate.save(output_mp3_path)
    print(f"[+] Audio generated: {output_mp3_path}")

def get_media_duration(file_path):
    cmd = [
        FFMPEG_EXE, "-i", file_path
    ]
    res = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # Extract Duration: 00:00:08.50
    for line in res.stderr.split('\n'):
        if "Duration:" in line:
            parts = line.split("Duration:")[1].split(",")[0].strip()
            h, m, s = parts.split(":")
            duration = float(h)*3600 + float(m)*60 + float(s)
            return duration
    return 8.0

async def build_presentation_video():
    temp_dir = "video_build_tmp"
    os.makedirs(temp_dir, exist_ok=True)
    
    video_segments = []
    
    total = len(SCENES)
    for i, scene in enumerate(SCENES):
        slide_img = os.path.join(temp_dir, f"slide_{i+1}.png")
        create_slide_image(scene, i, total, slide_img)
        
        audio_file = os.path.join(temp_dir, f"audio_{i+1}.mp3")
        try:
            await generate_audio_for_scene(scene["narration"], audio_file)
        except Exception as e:
            print(f"[-] Edge-TTS failed: {e}. Falling back to gTTS...")
            from gtts import gTTS
            tts = gTTS(text=scene["narration"], lang='en', slow=False)
            tts.save(audio_file)
            
        duration = get_media_duration(audio_file) + 1.2 # extra padding for clean transition
        
        segment_video = os.path.join(temp_dir, f"segment_{i+1}.mp4")
        # Build segment MP4 with image and audio
        cmd = [
            FFMPEG_EXE, "-y",
            "-loop", "1", "-i", slide_img,
            "-i", audio_file,
            "-c:v", "libx264", "-tune", "stillimage", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "192k",
            "-t", str(duration),
            "-shortest",
            segment_video
        ]
        subprocess.run(cmd, check=True)
        video_segments.append(segment_video)
        print(f"[+] Rendered video segment {i+1} (duration: {duration:.2f}s)")

    # Create concat list
    concat_list_file = os.path.join(temp_dir, "concat_list.txt")
    with open(concat_list_file, "w", encoding="utf-8") as f:
        for seg in video_segments:
            abs_seg = os.path.abspath(seg).replace('\\', '/')
            f.write(f"file '{abs_seg}'\n")

    output_final_mp4 = "PhishShield_AI_Project_Presentation.mp4"
    
    print("[*] Concatenating final presentation video...")
    concat_cmd = [
        FFMPEG_EXE, "-y",
        "-f", "concat", "-safe", "0",
        "-i", concat_list_file,
        "-c", "copy",
        output_final_mp4
    ]
    subprocess.run(concat_cmd, check=True)
    
    # Also copy to static folder for web preview
    static_video = os.path.join("static", "presentation_video.mp4")
    import shutil
    shutil.copyfile(output_final_mp4, static_video)
    
    print(f"\n[🎉 SUCCESS] Master Presentation Video created: {output_final_mp4}")
    print(f"[+] Web accessible copy: {static_video}")

if __name__ == "__main__":
    asyncio.run(build_presentation_video())
