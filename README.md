# BKSec2020-CTF

#         Hacked (Author: Q5Ca)
- Bài này thì khá đơn giản chỉ chúng ta chỉ cần tập trung vào file robots.txt sau đó ta sẽ tháy file sitemap.xml => nhận dc `http://52.163.126.205:24033/shell1337/` ok v là ta có thể chạy shell trên local , chỉ việc get the flag!. `BKSec{robots.txt_is_S0_interesting}`.
#         Admin watch tower (Author: Sudo)
- Mới vào trang web ta  thấy `total 12 drwxrwxr-x 2 1000 1000 4096 Mar 30 17:25 . drwxr-xr-x 1 root root 4096 Feb 26 11:59 .. -rw-rw-r-- 1 1000 1000 777 Mar 30 17:25 index.php`
  + Tôi đoán có thể control bằng get request và đầu ra của source code là `system($_GET)`, thử đầu tiên với parameter là `?cmd=ls` responts : `Hack con keci ` kèm theo video LỚN RỒI! tiếp tục thử các chữ cái đều bị chặn , xong thử tới các kí tự đặc biệt thì chỉ có 1 dấu `/` là sài được , nhưng kí tự tiếp theo sau dấu `/`chỉ cho phép các kí tự đặc biệt . 
  + V cũng không sao , thử dùng kí tự nối 2 câu lệnh trên linux là `;` với payload :`?cmd=/;ls ` xem có j hot. BOOM. respont trả về `index.php` 
  + V là có thể get the flag rồi ! payload hoàn chỉnh :`?cmd=/;cd ../../../../ ; cd etc ;cat h3r3_is_ur_FlAg.txt` flag:`BKSec{Ngh3___nh4c____DSK_____d1____kh0n9___t4o___d4m___ch3t___d4y}`.
 #        Shitcoin(Author: Q5Ca)
 -  Bài này khá thú vi đối với tôi , tuy làm ko giống ý đồ của tác giả, nhưng sau khi lấy được flag thì được tác giả có chỉ hướng đi , tôi cũng hiểu được phần nào tầm quan trọng của bài này . OK bây giờ tôi sẽ giải bài này theo cách của tôi!
 -  Bài này chỉ là gửi tiền cho người khác kèm theo là 1 message . tôi suy luận 2 trường hợp
    + 1 là tìm user có tiền trong database.
    + 2 là tự insert tiền cho mình (có khả quan hơn, và tôi chọn làm trước) .
 -  Sau khoảng thời gian lay hoay tìm chổ inject thì tôi cũng tìm được 1 chổ là message.
    + Message là chổ sẻ inject dữ liệu vào database , và sẽ select ra ở phia người nhận . Do đó ta có thể dùng inject select query để lấy các dữ liệu như tên bảng tên cột và value của các cột.  
    + Nhưng do tính cẩu thả , tôi fuzz hoa loa ,tuy có thử '||' nhưng lúc đầu không được nên tôi bỏ qua, và tôi đã dùng payload quá  chuối là `0"+ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))+"` thì nó sẽ chuyển các chữ cái thành số  hệ Dec và gửi cho ngừi nhận ,ta chỉ việc decode ra được các chữ và cứ thế theo cách này là ra được các tên bảng và các cột ``` ledger -> id,amount,sender_id,receiver_id,message   và   users -> id,username,password ``` . Nếu muốn lấy values của các cột thì dùng `0"+ascii(substr((select id from users limit 1 OFFSET 0),1,1))+"`.
    + Tiếp đó tôi thử dùng multi insert nhưng KHÔNG KHẢ QUAN payload `0"),("1000","OuSHJMNMVEXrvpYeU9OXY/Qk5V6eyxW7Le3QhZnUNySf6A6PoV36ySur86hZ1Fkx","OuSHJMNMVEXrvpYeU9OXY/Qk5V6eyxW7Le3QhZnUNySf6A6PoV36ySur86hZ1Fkx","HAH`  , với chuỗi dài nhất đó là id của ngừoi gửi và ngừơi nhận.
    + Quyết định chơi lun stacked query . update tiền cho mình ban đầu tôi dùng với payload `a"); UPDATE ledger SET amount=1000000-- -` mình sẽ bị -1000000 và người nhận sẽ dc 1000000 .Cứ chuyển qua chuyển lại thì sẽ đc tiền r mua flag thôi `BKSec{now_u_know_RELATIONAL_database}` 
 -  Ngoài ra các bạn có thể sử dụng payload :`"||(SELECT VERSION())||" ` để tìm version cũng như thây đổi 1 chút trong payload để tim các bảng và các cột và values cột nhanh nhất .  
 #          XML Suck(Author: Q5Ca)
 -  Bài này là mình solve cuối cùng , vì mình chưa rành về xxe nên việc làm nó cũng hơi khó khăn với mình . 
