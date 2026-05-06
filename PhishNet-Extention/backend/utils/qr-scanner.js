const jsQR = require('jsqr');
const { Jimp } = require('jimp'); // updated jimp import syntax for jimp 1.x or use default if older

/**
 * Extracts base64 images from HTML body and decodes QR codes.
 * Returns an array of URLs found in the QR codes.
 * @param {string} emailBodyHtml 
 * @returns {Promise<string[]>}
 */
async function extractAndDecodeQRCodes(emailBodyHtml) {
  if (!emailBodyHtml || typeof emailBodyHtml !== 'string') {
    return [];
  }

  const urls = [];
  
  // Regex to find base64 images in img src attributes
  // Matches data:image/[type];base64,[data]
  const base64Regex = /data:image\/[^;]+;base64,([^"']+)/gi;
  let match;

  while ((match = base64Regex.exec(emailBodyHtml)) !== null) {
    try {
      const base64Data = match[1];
      const buffer = Buffer.from(base64Data, 'base64');

      // Load image using Jimp
      const image = await Jimp.read(buffer);
      
      // Get image dimensions
      const width = image.bitmap.width;
      const height = image.bitmap.height;
      
      // Get raw pixel data (RGBA)
      const imageData = new Uint8ClampedArray(image.bitmap.data);

      // Decode QR code using jsQR
      const code = jsQR(imageData, width, height);

      if (code && code.data) {
        // If it's a URL, add to our list
        const text = code.data.trim();
        if (text.startsWith('http://') || text.startsWith('https://')) {
          urls.push(text);
          console.log('[QR Scanner] Found URL in QR Code:', text);
        }
      }
    } catch (err) {
      console.error('[QR Scanner] Error decoding image for QR code:', err.message);
      // Continue to next image
    }
  }

  return urls;
}

module.exports = {
  extractAndDecodeQRCodes
};
