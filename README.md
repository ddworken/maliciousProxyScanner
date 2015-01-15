#Scanning for Malicious Proxies

In the past few years, there has been a lot of press about HTTP proxies that transparently modify traffic to inject javascript for malicious purposes. There have been multiple presentations at DEFCON and blackhat about this topic and a variety of ways of exploiting it including: DDOS, credential theft, and even a distributed method of storage. 

Due to this, I decided to write a script to automatically scan proxies for malicious behavior such as: injecting javascript, modifying forms, and editing HTML. 

The first step was to get a list of proxies that are currently up and freely accessible. For this, I used a modified version of Dan McInerney’s Elite Proxy Finder. Originally, this script allowed for automated speed testing and discovery of elite proxies. I modified this script so as to: 

Output all types of proxies, not just elite proxies (since anonymity is not an issue).
Output proxies that support only http. This was done because proxies are not able to modify resources transmitted over SSL, so support for a protocol that I will not be testing is not needed.
Export a list of proxies and their ports
From there, I had a list of approximately 1000 active free proxies. While this is a relatively small number, I decided to move on with the experiment to see if there was any malicious behavior to be observed even in this small sample size. So on to the results!

In all 1500 proxies, there was no malicious traffic. What I mean by this is that no proxies transparently edited the traffic without making it very clear that one was not reaching the requested website. There was no injection of javascript. There was no modification of forms. Absolutely no interesting modifications. 

Thus the next step is going to be to use masscan to scan the ipv4 address space to look for free proxies, then once again search for malicious behavior.

The code used for this post will be posted here once I clean it up a little bit.

Update: I updated the script slightly so as to increase the number of proxies it discovered. With the addition of the updated script, I have discovered a number of malicious proxies that are currently active. 

Here is a list of all proxies detected with errant behavior and a description of their errant behavior.

=======

The proxy server at

221.183.16.219:00080

modifies HTML sent over HTTP to add the following code to every webpage

<script type=’text/javascript’ charset=’utf-8’ src=’http://www.adfocus.com.cn/adscript/adfocus.js’></script>

Sadly, the adfocus.com.cn domain is not currently accessible, so I cannot view the injected javascript. Based off of the URL of the injected javascript, two conclusions can be made. 

It is javascript used to automatically inject ads into websites accessed over HTTP. This seems to be the most obvious solution since the domain is “adfocus.com.cn” and the javascript file is stored in the “adscript” folder and is called “adfocus.js”. This would make sense since it is a free proxy, the owners of the proxy are likely trying to monetize the business. 
However, it seems like this might be what we are supposed to think. I say this because the javascript is hosted on the adfocus.com.cn domain, very similar to the legitimate adfocus.com. It might be that the administrators of this proxy are attempting to capture the reputation of adfocus.com so as to prove the legitimate nature of the injected code. This makes me wonder whether this code serves a more malicious purpose. The injected javascript could do anything from exploit the computer to be part of a botnet to be part of a distributed filesystem. 

=======

The proxy server at

115.239.210.199:80

automatically strips all HTML comments from the transmitted data. While this does not have any obvious negative effect, it still modifies the transmitted HTML which is an inherently bad thing for any proxy server. 

=======

The proxy server at

60.194.40.198:8118

modifies HTML sent over HTTP to add the following code to every webpage

<script type=”text/javascript” charset=”utf-8” mediaproAccountID=”0” mediaproSlotID=”0” usermac=”” src=”/7b26d4601fbe440b35e496a0fcfa15f7/000c4347fbe8/w1/i.js” async=”async” defer></script><meta http-equiv=”Content-Type” content=”text/html; charset=UTF-8” />

=======

The proxy server at

122.225.106.35:80

modifies HTML sent over HTTP to add the following code to every webpage

<link rel=”stylesheet” type=”text/css” href=”http://ads.adt100.com/bottom.css” /><div id=”center_xad” class=”cwindow_xad”> <div class=”center_title_xad”> <img onclick=”closeWindow()” width=”15px” height=”15px” src=”http://ads.adt100.com/images/close_btn.gif”> </div> <div id=’center_xad_cnt’ class=”injection_content”></div></div><div id=”right_xad” class=”window_xad”> <div class=”right_title_xad”><img onclick=”closeWindow()” width=”15px” height=”15px” src=”http://ads.adt100.com/images/close_btn.gif”></div><div id=’right_xad_cnt’ class=”injection_content”></div></div><script type=”text/javascript” src=”http://ads.adt100.com/bottom.js”></script></body>

This code does a number of interesting things. First of all, it adds a new CSS style sheet. While the style sheet does not do anything malicious (instead choosing to allow the page to appear normally) it is clearly malicious in its purpose, the stylesheet is not the key to the malicious code.The interesting part is here. As my knowledge of javascript is quite limited, I’m going to stop my analysis here. But based off of a quick read through of the code, it seems to be malicious in nature considering the injection of a flash object attempting to download an exe.

=======

So far, I have only analyzed a few select malicious proxies. A full data dump from running this script is available in the Github repo here if anyone wants to give an automated analysis a shot (6500+ lines).
