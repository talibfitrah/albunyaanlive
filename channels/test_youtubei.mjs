import { Innertube } from 'youtubei.js';

async function main() {
  const yt = await Innertube.create();

  // Get channel live stream
  const channelUrl = process.argv[2] || 'https://www.youtube.com/@SaudiSunnahTv/live';

  console.log('Fetching:', channelUrl);

  try {
    // Extract video ID from channel live URL
    const info = await yt.getInfo(channelUrl);

    console.log('Title:', info.basic_info?.title);
    console.log('Is Live:', info.basic_info?.is_live);
    console.log('Video ID:', info.basic_info?.id);

    // Get HLS manifest
    const hlsUrl = info.streaming_data?.hls_manifest_url;
    if (hlsUrl) {
      console.log('HLS URL:', hlsUrl);
    } else {
      console.log('No HLS URL found');
      // Try to get from formats
      const formats = info.streaming_data?.formats || [];
      const hlsFormats = info.streaming_data?.adaptive_formats || [];
      console.log('Formats available:', formats.length);
      console.log('Adaptive formats:', hlsFormats.length);
    }
  } catch (err) {
    console.error('Error:', err.message);
  }
}

main();
