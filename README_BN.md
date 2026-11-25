# EMON JWT API v2 (OB55)

`/token?uid=&password=&server_name=BD|IND`  ->  JWT

- নতুন: সফল OB55 MajorLogin বডি (`majorlogin_new.py`) ব্যবহার করে (আগেরটা পুরনো 1.132.4 বডি ছিল)
- protobuf লাইব্রেরি/pb2 লাগে না
- `region`, `client_url`, `expires_at` ফেরত দেয়
- একই uid+password বারবার লগিন করে না (ক্যাশ)
- `API_KEY` সেট করলে `&key=` লাগবে
- Owner: EMON
