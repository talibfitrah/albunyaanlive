#!/bin/bash

sudo kill -9 $(ps aux | grep -i start_stream | awk '{print$2}')
sudo kill -9 $(ps aux | grep -i ffmpeg | awk '{print$2}')
sudo kill -9 $(ps aux | grep -i hls_background_job | awk '{print$2}')

rm -rf /var/www/html/stream/hls/basmah/*
rm -rf /var/www/html/stream/hls/zaad/*
rm -rf /var/www/html/stream/hls/mekkah-quran/*
rm -rf /var/www/html/stream/hls/rawdah/*
rm -rf /var/www/html/stream/hls/almajd/*
rm -rf /var/www/html/stream/hls/maaliy/*
rm -rf /var/www/html/stream/hls/eman/*
rm -rf /var/www/html/stream/hls/ssad/*
rm -rf /var/www/html/stream/hls/huda/*
rm -rf /var/www/html/stream/hls/sunnah/*
rm -rf /var/www/html/stream/hls/daal/*
rm -rf /var/www/html/stream/hls/maassah/*
rm -rf /var/www/html/stream/hls/sharjah/*
rm -rf /var/www/html/stream/hls/almajd-kids/*
rm -rf /var/www/html/stream/hls/natural/*
rm -rf /var/www/html/stream/hls/almajd-islamic-science/*
rm -rf /var/www/html/stream/hls/almajd-quran/*
rm -rf /var/www/html/stream/hls/almajd-3aamah/*
rm -rf /var/www/html/stream/hls/taghareed/*
rm -rf /var/www/html/stream/hls/nour/*
rm -rf /var/www/html/stream/hls/makkah/*
rm -rf /var/www/html/stream/hls/sharjah2/*
rm -rf /var/www/html/stream/hls/aluthaymin/*
rm -rf /var/www/html/stream/hls/quran-radio/*
rm -rf /var/www/html/stream/hls/nida/*
rm -rf /var/www/html/stream/hls/hadith-almajd/*
rm -rf /var/www/html/stream/hls/taasi3ah/*
rm -rf /var/www/html/stream/hls/almajd-news/*
rm -rf /var/www/html/stream/hls/arrahmah/*
rm -rf /var/www/html/stream/hls/safa/*
rm -rf /var/www/html/stream/hls/assalam/*
rm -rf /var/www/html/stream/hls/nine/*
rm -rf /var/www/html/stream/hls/nada/*
rm -rf /var/www/html/stream/hls/saad/*
rm -rf /var/www/html/stream/hls/almajd-documentary/*
sudo rm -rf /home/msa/Development/scripts/albunyaan/channels/logs/.log.old
