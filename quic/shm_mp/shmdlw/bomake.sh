make -j 8
scp -r /home/emma/mvfst/quic/shm_mp/shmdlw root@192.168.80.144:/home/emma/mvfst/quic/shm_mp/

scp -r /home/emma/mvfst/shm root@192.168.80.144:/home/emma/mvfst/

scp -r /home/emma/mvfst/quic/client root@192.168.80.144:/home/emma/mvfst/quic/

scp -r /home/emma/mvfst/quic/server root@192.168.80.144:/home/emma/mvfst/quic/

scp -r /home/emma/mvfst/quic/api root@192.168.80.144:/home/emma/mvfst/quic/

scp shmdlw user_client app_server config.txt cli.conf root@192.168.80.144:/home/emma/mvfst/_build/build/quic/shm_mp/
