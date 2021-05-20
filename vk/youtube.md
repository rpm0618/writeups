# VK's 1024 Subscriber Special

Recently vk posted a [cryptic message](https://www.youtube.com/channel/UCLNOkRPLkLOUGkSDx5CbxdA/community?lb=Ugwty837XikkhekSoKN4AaABCQ) on their youtube channel, leading to a small puzzle/arg announcing their next video.

Text of the message:

```
So I hit a large round number milestone recently: 1024 subscribers!
To c͘ele͡br̡̕at̅́̀͜e, I'̸m̷ ϸϴϛϚ౹Յڪٓڬܶޓ୴ணஞທ 
aHR0cHM6Ly9jb2RlZGlnLm5ldC8lMTQlMTklMTUlMGMlMGQucG5nCg==
```

The only relevant part (for the puzzle) is the final line. It is encoded using base64, a common format computers use to encode data. Since it's a well known format, there are tools such as https://www.base64decode.org/ you can use to easily decode it.

The above message decodes to `https://codedig.net/%14%19%15%0c%0d.png`, which links to an image (we'll get back to the weird filename later):

![brain image](image.png)

In the top left corner there's an 8x9 rectangle of black and pixels.

![top left rectangle](topLeftData.png)

Being 8 pixels wide is an indicator we can probably treat each row of pixels as a byte (black pixels are 0, white pixels are 1s).

If we do that, and reference an ASCII chart ([here](https://www.rapidtables.com/convert/number/binary-to-ascii.html) for example), the first 5 characters of the message decode to "UTC: ", implying the following information is a timestamp in UTC. We can treat them as the 4 bytes of a 32 bit integer, and we get `1621695600`. If we treat that as a unix timestamp, we can convert that to a time/date (using something like https://www.epochconverter.com/). The final decoding of the top left rectangle is:

```UTC: May 22nd 2021 15:00```

Much harder to see is another rectangle of pixels in the bottom right corner. The data is being stored in the alpha channel, so it is difficult to see. Putting a white background behind the image makes it *slightly* easier to see:

![bottom right data](bottomRightData.png)

With some squinting, this can be decoded in the same way as the first one. This one decodes to `intro.mp4`. We can pop it on to the end of the domain for the original image, which links to a short video: https://codedig.net/intro.mp4

The video shows a quick image of vk's logo, and then the text `net.minecraft.entity.ai` getting typed out on screen.

From these two pieces on information, we conclude that vk is releasing a video about minecraft AI on May 22nd.

Finally, the image file name is a set of 5 bytes represented using URL encoding. These aren't nice ASCII characters. vk indicated in discord that the file name was encrypted using a "5 byte key, simple operation between each pair of bytes". XOR is a common operation used in these types of ciphers, and a little trial and error gives a key of "brain" for a plaintext of "vktec".