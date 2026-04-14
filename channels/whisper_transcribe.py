#!/usr/bin/env python3
"""
Whisper AI Transcription Script
Uses faster-whisper with large-v3 model for high-accuracy multilingual transcription.
Supports: Arabic (ar), English (en), Dutch (nl) — and 90+ other languages.

Usage:
  python3 whisper_transcribe.py <audio_or_video_file> [--language ar|en|nl|auto] [--output srt|vtt|txt|json|all]

Examples:
  python3 whisper_transcribe.py recording.mp3
  python3 whisper_transcribe.py recording.mp3 --language ar
  python3 whisper_transcribe.py video.mp4 --output srt
  python3 whisper_transcribe.py podcast.wav --language auto --output all
"""

import argparse
import json
import os
import sys
import time

from faster_whisper import WhisperModel


def format_timestamp(seconds, fmt="srt"):
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = seconds % 60
    if fmt == "vtt":
        return f"{hours:02d}:{minutes:02d}:{secs:06.3f}"
    return f"{hours:02d}:{minutes:02d}:{secs:06.3f}".replace(".", ",")


def write_srt(segments, path):
    with open(path, "w", encoding="utf-8") as f:
        for i, seg in enumerate(segments, 1):
            f.write(f"{i}\n")
            f.write(f"{format_timestamp(seg['start'])} --> {format_timestamp(seg['end'])}\n")
            f.write(f"{seg['text'].strip()}\n\n")


def write_vtt(segments, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("WEBVTT\n\n")
        for i, seg in enumerate(segments, 1):
            f.write(f"{i}\n")
            f.write(f"{format_timestamp(seg['start'], 'vtt')} --> {format_timestamp(seg['end'], 'vtt')}\n")
            f.write(f"{seg['text'].strip()}\n\n")


def write_txt(segments, path):
    with open(path, "w", encoding="utf-8") as f:
        for seg in segments:
            f.write(f"{seg['text'].strip()}\n")


def write_json(segments, info, path):
    data = {
        "language": info.language,
        "language_probability": round(info.language_probability, 4),
        "duration": round(info.duration, 2),
        "segments": segments,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Transcribe audio/video with Whisper large-v3")
    parser.add_argument("input", help="Path to audio or video file")
    parser.add_argument("--language", "-l", default="auto",
                        help="Language code: ar, en, nl, or auto (default: auto)")
    parser.add_argument("--output", "-o", default="all",
                        choices=["srt", "vtt", "txt", "json", "all"],
                        help="Output format (default: all)")
    parser.add_argument("--beam-size", type=int, default=5,
                        help="Beam size for decoding (default: 5)")
    parser.add_argument("--device", default="cuda",
                        choices=["cuda", "cpu"],
                        help="Device to use (default: cuda)")
    parser.add_argument("--compute-type", default="float16",
                        choices=["float16", "int8_float16", "int8"],
                        help="Compute type (default: float16)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    base = os.path.splitext(args.input)[0]
    lang = None if args.language == "auto" else args.language

    print(f"Loading Whisper large-v3 on {args.device} ({args.compute_type})...")
    t0 = time.time()
    model = WhisperModel("large-v3", device=args.device, compute_type=args.compute_type)
    print(f"Model loaded in {time.time() - t0:.1f}s")

    print(f"Transcribing: {args.input}")
    if lang:
        print(f"Language: {lang}")
    else:
        print("Language: auto-detect")

    t0 = time.time()
    segments_gen, info = model.transcribe(
        args.input,
        beam_size=args.beam_size,
        language=lang,
        vad_filter=True,
        vad_parameters=dict(min_silence_duration_ms=500),
        word_timestamps=True,
        condition_on_previous_text=True,
    )

    segments = []
    for seg in segments_gen:
        segments.append({
            "start": round(seg.start, 3),
            "end": round(seg.end, 3),
            "text": seg.text,
        })
        print(f"  [{format_timestamp(seg.start, 'vtt')} -> {format_timestamp(seg.end, 'vtt')}] {seg.text.strip()}")

    elapsed = time.time() - t0
    print(f"\nDetected language: {info.language} (confidence: {info.language_probability:.1%})")
    print(f"Duration: {info.duration:.1f}s | Transcribed in {elapsed:.1f}s ({info.duration/elapsed:.1f}x realtime)")
    print(f"Segments: {len(segments)}")

    outputs = []
    formats = ["srt", "vtt", "txt", "json"] if args.output == "all" else [args.output]

    for fmt in formats:
        path = f"{base}.{fmt}"
        if fmt == "srt":
            write_srt(segments, path)
        elif fmt == "vtt":
            write_vtt(segments, path)
        elif fmt == "txt":
            write_txt(segments, path)
        elif fmt == "json":
            write_json(segments, info, path)
        outputs.append(path)
        print(f"Saved: {path}")


if __name__ == "__main__":
    main()
