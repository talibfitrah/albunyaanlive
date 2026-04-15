# Channel-config shim for reflex E2E. Only the stream_url lines matter —
# reflex_watcher.sh greps them to build the per-channel backup list; it
# never sources or executes this file. The "runnable" supervisor config
# for this channel lives next to this in test_channel.sh.
stream_url="http://127.0.0.1:18080/master.m3u8"
stream_url_backup1="http://127.0.0.1:18081/master.m3u8"
