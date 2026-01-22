#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Default to local browser resolver for all YouTube URLs (safe fallback if service absent)
export YOUTUBE_BROWSER_RESOLVER="${YOUTUBE_BROWSER_RESOLVER:-http://127.0.0.1:8088}"

./channel_almajd_aamah_revised.sh
./channel_almajd_kids_revised.sh
./channel_almajd_doc_revised.sh
./channel_maassah_revised.sh
./channel_almajd_quran_revised.sh
./channel_almajd_science_revised.sh
./channel_almajd_nature_revised.sh
./channel_basmah_revised.sh
./channel_mecca_quran_revised.sh
./channel_daal_revised.sh
./channel_rawdah_revised.sh
./channel_sunnah_revised.sh
./channel_zaad_revised.sh
./channel_anees_revised.sh
./channel_almajd_news.sh
./channel_arrahmah.sh
./channel_almajd_hadith.sh
./channel_quran.sh
./channel_nada_revised.sh
./channel_ajaweed_revised.sh
