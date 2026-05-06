/**
 * PhishNet Blog System — Modern Grid Layout
 * Static 110 articles with category filtering, search, and pagination
 */

class BlogSystem {
  constructor() {
    this.perPage = 12;
    this.currentPage = 1;
    this.currentCategory = 'all';
    this.searchQuery = '';
    this.allBlogs = this.getBuiltInBlogs();
    // Assign reliable placeholder images (picsum.photos with unique seeds)
    this.allBlogs.forEach(function(b, i) {
      b.image = 'https://picsum.photos/seed/pn' + i + '/600/340';
    });
    this.filteredBlogs = [...this.allBlogs];
    this.init();
  }

  init() {
    this.buildCategoryPills();
    this.applyFilters();
    this.setupEvents();
  }

  /* ── Category colours ── */
  catStyle(cat) {
    const m = {
      'Phishing':          { bg: '#FF4D4D18', c: '#FF4D4D', bc: '#FF4D4D44' },
      'Threat Analysis':   { bg: '#FFC10718', c: '#F59E0B', bc: '#F59E0B44' },
      'Security Tips':     { bg: '#10B98118', c: '#10B981', bc: '#10B98144' },
      'Email Security':    { bg: '#0B63D918', c: '#3B82F6', bc: '#3B82F644' },
      'Enterprise':        { bg: '#A855F718', c: '#A855F7', bc: '#A855F744' },
      'Case Studies':      { bg: '#F9731618', c: '#F97316', bc: '#F9731644' },
      'Privacy & Data':    { bg: '#EC489918', c: '#EC4899', bc: '#EC489944' },
      'Malware':           { bg: '#EF444418', c: '#EF4444', bc: '#EF444444' },
      'Social Engineering':{ bg: '#8B5CF618', c: '#8B5CF6', bc: '#8B5CF644' },
      'Mobile Security':   { bg: '#06B6D418', c: '#06B6D4', bc: '#06B6D444' },
      'AI & ML Security':  { bg: '#6366F118', c: '#6366F1', bc: '#6366F144' },
      'Cloud Security':    { bg: '#14B8A618', c: '#14B8A6', bc: '#14B8A644' },
    };
    return m[cat] || { bg: '#0B63D918', c: '#0B63D9', bc: '#0B63D944' };
  }

  /* ── Category pills ── */
  buildCategoryPills() {
    const wrap = document.getElementById('category-pills');
    if (!wrap) return;

    const counts = {};
    this.allBlogs.forEach(b => { counts[b.category] = (counts[b.category] || 0) + 1; });

    const cats = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);

    let html = '<button class="blg-pill active" data-cat="all">All<span class="blg-pill-n">' + this.allBlogs.length + '</span></button>';
    cats.forEach(cat => {
      html += '<button class="blg-pill" data-cat="' + cat + '">' + cat + '<span class="blg-pill-n">' + counts[cat] + '</span></button>';
    });
    wrap.innerHTML = html;

    wrap.addEventListener('click', e => {
      const btn = e.target.closest('.blg-pill');
      if (!btn) return;
      wrap.querySelectorAll('.blg-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      this.currentCategory = btn.dataset.cat;
      this.currentPage = 1;
      this.applyFilters();
    });
  }

  /* ── Filtering + search ── */
  applyFilters() {
    let list = [...this.allBlogs];

    if (this.currentCategory !== 'all') {
      list = list.filter(b => b.category === this.currentCategory);
    }

    if (this.searchQuery) {
      const q = this.searchQuery.toLowerCase();
      list = list.filter(b =>
        b.title.toLowerCase().includes(q) ||
        b.summary.toLowerCase().includes(q) ||
        b.category.toLowerCase().includes(q) ||
        b.tags.some(t => t.toLowerCase().includes(q))
      );
    }

    this.filteredBlogs = list;
    this.render();
  }

  /* ── Render grid ── */
  render() {
    const container = document.getElementById('blog-posts-container');
    const countEl = document.getElementById('blog-count');
    if (!container) return;

    const total = this.filteredBlogs.length;
    // Page 1 shows 1 extra item so featured card + 12 regular = 4 full rows of 3
    const hasFeatured = (this.currentPage === 1 && !this.searchQuery);
    const page1Size = this.perPage + 1;
    const pages = (!this.searchQuery && total > page1Size)
      ? 1 + Math.ceil((total - page1Size) / this.perPage)
      : Math.ceil(total / this.perPage);
    if (this.currentPage > pages) this.currentPage = pages || 1;
    let start, count;
    if (this.currentPage === 1) {
      start = 0;
      count = hasFeatured ? page1Size : this.perPage;
    } else {
      start = page1Size + (this.currentPage - 2) * this.perPage;
      count = this.perPage;
    }
    const slice = this.filteredBlogs.slice(start, start + count);

    if (countEl) countEl.textContent = total + ' article' + (total !== 1 ? 's' : '');

    if (!slice.length) {
      container.innerHTML = '<div class="blg-empty">No articles found. Try a different search or category.</div>';
      this.renderPagination(0);
      return;
    }

    let html = '';
    slice.forEach((blog, i) => {
      const cs = this.catStyle(blog.category);
      const isFirst = (this.currentPage === 1 && i === 0 && !this.searchQuery);

      if (isFirst) {
        html += '<article class="blg-card blg-featured">' +
          '<div class="blg-card-img-wrap"><img class="blg-card-img" src="' + blog.image + '" alt="" onerror="this.style.opacity=\'0\'" loading="lazy"></div>' +
          '<div class="blg-card-body">' +
            '<div class="blg-feat-tag"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26"/></svg> Featured</div>' +
            '<div class="blg-card-top">' +
              '<span class="blg-badge" style="background:' + cs.bg + ';color:' + cs.c + ';border:1px solid ' + cs.bc + '">' + blog.category + '</span>' +
            '</div>' +
            '<h2 class="blg-card-title"><a href="' + blog.link + '" target="_blank" rel="noopener">' + this.esc(blog.title) + '</a></h2>' +
            '<p class="blg-card-excerpt">' + this.esc(blog.summary) + '</p>' +
            '<div class="blg-card-foot">' +
              '<span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>' + blog.date + '</span>' +
              '<span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' + blog.readTime + '</span>' +
            '</div>' +
          '</div>' +
        '</article>';
      } else {
        html += '<article class="blg-card">' +
          '<div class="blg-card-img-wrap"><img class="blg-card-img" src="' + blog.image + '" alt="" onerror="this.style.opacity=\'0\'" loading="lazy"></div>' +
          '<div class="blg-card-body">' +
            '<div class="blg-card-top">' +
              '<span class="blg-badge" style="background:' + cs.bg + ';color:' + cs.c + ';border:1px solid ' + cs.bc + '">' + blog.category + '</span>' +
            '</div>' +
            '<h3 class="blg-card-title"><a href="' + blog.link + '" target="_blank" rel="noopener">' + this.esc(blog.title) + '</a></h3>' +
            '<p class="blg-card-excerpt">' + this.esc(blog.summary) + '</p>' +
            '<div class="blg-card-foot">' +
              '<span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>' + blog.date + '</span>' +
              '<span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' + blog.readTime + '</span>' +
            '</div>' +
          '</div>' +
        '</article>';
      }
    });

    container.innerHTML = html;
    this.renderPagination(pages);

    // Smooth scroll to top of grid on page change (not on initial load)
    if (this._hasRendered) {
      const section = document.querySelector('.blg-filters');
      if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    this._hasRendered = true;
  }

  /* ── Pagination ── */
  renderPagination(pages) {
    const wrap = document.getElementById('blog-pagination');
    if (!wrap) return;
    if (pages <= 1) { wrap.innerHTML = ''; return; }

    const arrowL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>';
    const arrowR = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>';

    let html = '<button class="blg-pag-prev" data-p="prev"' + (this.currentPage === 1 ? ' disabled' : '') + '>' + arrowL + ' Previous</button>';

    html += '<div class="blg-pag-nums">';
    const range = this.pagRange(this.currentPage, pages);
    range.forEach(p => {
      if (p === '...') {
        html += '<span class="blg-pag-dots">\u2026</span>';
      } else {
        html += '<button class="blg-pag-btn' + (p === this.currentPage ? ' active' : '') + '" data-p="' + p + '">' + p + '</button>';
      }
    });
    html += '</div>';

    html += '<button class="blg-pag-next" data-p="next"' + (this.currentPage === pages ? ' disabled' : '') + '>Next ' + arrowR + '</button>';
    html += '<span class="blg-pag-info">Page ' + this.currentPage + ' of ' + pages + '</span>';
    wrap.innerHTML = html;

    wrap.onclick = (e) => {
      const btn = e.target.closest('.blg-pag-btn') || e.target.closest('.blg-pag-prev') || e.target.closest('.blg-pag-next');
      if (!btn || btn.disabled) return;
      const v = btn.dataset.p;
      if (v === 'prev') this.currentPage--;
      else if (v === 'next') this.currentPage++;
      else this.currentPage = parseInt(v);
      this.render();
    };
  }

  pagRange(cur, total) {
    if (total <= 7) return Array.from({ length: total }, function(_, i) { return i + 1; });
    if (cur <= 3) return [1, 2, 3, 4, '...', total];
    if (cur >= total - 2) return [1, '...', total - 3, total - 2, total - 1, total];
    return [1, '...', cur - 1, cur, cur + 1, '...', total];
  }

  /* ── Events ── */
  setupEvents() {
    const search = document.getElementById('blog-search');
    if (search) {
      let timer;
      search.addEventListener('input', function(e) {
        clearTimeout(timer);
        const self = window.blogSystem;
        timer = setTimeout(function() {
          self.searchQuery = e.target.value.trim();
          self.currentPage = 1;
          self.applyFilters();
        }, 250);
      });
    }
  }

  esc(t) { var d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

  /* ── 110 built-in blog articles ── */
  getBuiltInBlogs() {
    return [
      // ─── Phishing (12) ───
      { title:'How Phishing Attacks Work: A Complete Guide for 2026', summary:'Phishing remains the #1 attack vector for cybercriminals. Learn how attackers craft convincing emails, clone login pages, and use social engineering to steal credentials.', date:'Feb 10, 2026', readTime:'8 min', category:'Phishing', tags:['Phishing','Social Engineering','Email'], link:'https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'The Rise of QR Code Phishing (Quishing)', summary:'QR codes in emails and physical locations are being weaponized to redirect victims to phishing sites. Learn to identify malicious QR codes and protect yourself.', date:'Feb 5, 2026', readTime:'6 min', category:'Phishing', tags:['QR Code','Quishing','Mobile'], link:'https://www.bleepingcomputer.com/tag/qr-code/', image:'https://images.unsplash.com/photo-1595079676339-1534801ad6cf?w=600&h=340&fit=crop' },
      { title:'Spear Phishing vs Whale Phishing: What\'s the Difference?', summary:'Targeted phishing campaigns come in many forms. Understand the differences between mass phishing, spear phishing, and whale phishing attacks that target executives.', date:'Jan 28, 2026', readTime:'7 min', category:'Phishing', tags:['Spear Phishing','Whale Phishing','Targeting'], link:'https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'Smishing: The SMS Phishing Epidemic', summary:'Text message phishing is exploding. Fake delivery notifications, bank alerts, and government messages trick millions. Here\'s how to spot and avoid smishing.', date:'Jan 20, 2026', readTime:'5 min', category:'Phishing', tags:['Smishing','SMS','Mobile Security'], link:'https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams', image:'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&h=340&fit=crop' },
      { title:'Voice Phishing (Vishing): When Attackers Call You', summary:'AI-generated voices now impersonate banks, tech support, and even family members. Learn how vishing attacks work and the telltale signs of a fraudulent call.', date:'Jan 12, 2026', readTime:'6 min', category:'Phishing', tags:['Vishing','Voice AI','Phone Scams'], link:'https://www.fbi.gov/how-can-we-help-you/safety-resources/scams-and-safety', image:'https://images.unsplash.com/photo-1534536281715-e28d76689b4d?w=600&h=340&fit=crop' },
      { title:'Callback Phishing: The New Trend Bypassing Email Filters', summary:'Attackers send emails with phone numbers instead of links, bypassing security filters. Victims call back and are socially engineered into installing malware.', date:'Jan 5, 2026', readTime:'7 min', category:'Phishing', tags:['Callback Phishing','BazarCall','Social Engineering'], link:'https://www.crowdstrike.com/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'Angler Phishing on Social Media Platforms', summary:'Fake customer support accounts on Twitter, Facebook, and Instagram lure victims into sharing credentials. Learn to verify official brand accounts.', date:'Dec 28, 2025', readTime:'5 min', category:'Phishing', tags:['Social Media','Angler Phishing','Brand Impersonation'], link:'https://krebsonsecurity.com/', image:'https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=600&h=340&fit=crop' },
      { title:'Clone Phishing: When Attackers Replay Legitimate Emails', summary:'Attackers intercept real emails and resend them with malicious attachments or links. This sophisticated technique is hard to detect without proper tools.', date:'Dec 20, 2025', readTime:'6 min', category:'Phishing', tags:['Clone Phishing','Email Replay','Detection'], link:'https://www.proofpoint.com/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Pharming Attacks: Phishing Without the Bait', summary:'DNS poisoning and hosts file modification redirect users to fake websites without any email or message. Understand how pharming works at the infrastructure level.', date:'Dec 14, 2025', readTime:'8 min', category:'Phishing', tags:['Pharming','DNS Poisoning','Infrastructure'], link:'https://www.cloudflare.com/learning/dns/dns-cache-poisoning/', image:'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&h=340&fit=crop' },
      { title:'Browser-in-the-Browser (BitB) Phishing Attacks', summary:'Attackers create fake browser popup windows that look identical to real authentication prompts. This technique fools even security-aware users.', date:'Dec 7, 2025', readTime:'7 min', category:'Phishing', tags:['BitB','Browser Attack','Credential Theft'], link:'https://mrd0x.com/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'Phishing-as-a-Service: The Criminal Marketplace', summary:'Underground marketplaces now sell complete phishing kits with hosting, templates, and support. This industrialization makes phishing accessible to anyone.', date:'Nov 30, 2025', readTime:'9 min', category:'Phishing', tags:['PhaaS','Dark Web','Cybercrime'], link:'https://www.europol.europa.eu/', image:'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=600&h=340&fit=crop' },
      { title:'HTTPS Doesn\'t Mean Safe: The SSL Phishing Myth', summary:'Over 80% of phishing sites now use HTTPS. The padlock icon only means encrypted transport, not trustworthiness. Learn what to really look for in URLs.', date:'Nov 22, 2025', readTime:'5 min', category:'Phishing', tags:['HTTPS','SSL','URL Analysis'], link:'https://letsencrypt.org/', image:'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&h=340&fit=crop' },

      // ─── Threat Analysis (10) ───
      { title:'Typosquatting: When One Misspelled Letter Steals Your Password', summary:'Attackers register domains like googlr.com to trick users. PhishNet detects 11 types of typosquatting including homograph attacks and combo-squatting.', date:'Feb 8, 2026', readTime:'6 min', category:'Threat Analysis', tags:['Typosquatting','Homograph','Domain'], link:'https://www.csoonline.com/article/570381/what-is-typosquatting.html', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'SSL Certificate Red Flags: What Your Browser Won\'t Tell You', summary:'Self-signed certificates, newly issued certs, and wildcard certificates on suspicious domains are indicators of phishing. Learn how to inspect SSL chains.', date:'Feb 3, 2026', readTime:'7 min', category:'Threat Analysis', tags:['SSL','Certificates','HTTPS'], link:'https://www.cloudflare.com/learning/ssl/what-is-an-ssl-certificate/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'How AI and ML Detect Zero-Day Phishing', summary:'Traditional blocklists can\'t stop new phishing sites. BERT-based ML models analyze URL patterns and behavioral signals to catch phishing pages within minutes.', date:'Jan 30, 2026', readTime:'9 min', category:'Threat Analysis', tags:['Machine Learning','AI','Zero-Day'], link:'https://research.google/pubs/', image:'https://images.unsplash.com/photo-1677442136019-21780ecad995?w=600&h=340&fit=crop' },
      { title:'DNS Tunneling: Exfiltrating Data Through Domain Queries', summary:'Attackers encode stolen data in DNS queries to bypass firewalls. This stealthy technique can operate undetected for months in enterprise networks.', date:'Jan 15, 2026', readTime:'8 min', category:'Threat Analysis', tags:['DNS','Data Exfiltration','Network Security'], link:'https://www.paloaltonetworks.com/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Adversary-in-the-Middle (AiTM) Phishing Explained', summary:'Modern phishing proxies like EvilGinx intercept authentication tokens in real-time, bypassing MFA. Understanding this threat is critical for defense planning.', date:'Jan 8, 2026', readTime:'10 min', category:'Threat Analysis', tags:['AiTM','MFA Bypass','EvilGinx'], link:'https://www.microsoft.com/en-us/security/blog/', image:'https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=600&h=340&fit=crop' },
      { title:'Credential Stuffing: Weaponizing Data Breaches', summary:'Billions of leaked credentials are tested against websites automatically. Understanding credential stuffing helps explain why unique passwords are essential.', date:'Dec 30, 2025', readTime:'6 min', category:'Threat Analysis', tags:['Credential Stuffing','Data Breach','Passwords'], link:'https://haveibeenpwned.com/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'Deepfake Audio in Targeted Attacks', summary:'AI-generated voice clones have been used to authorize fraudulent wire transfers. The technology is becoming cheaper and more accessible to criminals.', date:'Dec 20, 2025', readTime:'7 min', category:'Threat Analysis', tags:['Deepfake','AI','Voice Clone'], link:'https://www.darkreading.com/', image:'https://images.unsplash.com/photo-1589254065878-42c9da997008?w=600&h=340&fit=crop' },
      { title:'Supply Chain Attacks: When Trust Becomes a Weapon', summary:'Attackers compromise trusted software vendors to distribute malware to thousands of organizations simultaneously. SolarWinds was just the beginning.', date:'Dec 12, 2025', readTime:'9 min', category:'Threat Analysis', tags:['Supply Chain','SolarWinds','Vendor Risk'], link:'https://www.cisa.gov/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'Steganography in Modern Cyber Attacks', summary:'Hiding malicious code inside images, audio files, and documents allows attackers to bypass security scanners. Learn how steganographic payloads work.', date:'Dec 5, 2025', readTime:'8 min', category:'Threat Analysis', tags:['Steganography','Malware','Evasion'], link:'https://www.welivesecurity.com/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'The MITRE ATT&CK Framework for Phishing Defense', summary:'Map phishing techniques to MITRE ATT&CK tactics to build comprehensive detection strategies. A practical guide for security teams.', date:'Nov 28, 2025', readTime:'11 min', category:'Threat Analysis', tags:['MITRE','ATT&CK','Framework'], link:'https://attack.mitre.org/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },

      // ─── Security Tips (12) ───
      { title:'10 Signs a Website Is a Phishing Scam', summary:'From suspicious URLs to fake SSL certificates, learn the red flags that expose phishing sites. Real examples show what automated tools catch that humans miss.', date:'Feb 5, 2026', readTime:'5 min', category:'Security Tips', tags:['Phishing Detection','URL Analysis','Tips'], link:'https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams', image:'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=600&h=340&fit=crop' },
      { title:'Why Two-Factor Authentication Isn\'t Enough Anymore', summary:'Attackers use real-time phishing proxies to intercept 2FA tokens. Learn about phishing-resistant MFA options like FIDO2 security keys and passkeys.', date:'Jan 20, 2026', readTime:'7 min', category:'Security Tips', tags:['2FA','MFA','FIDO2','Passkeys'], link:'https://fidoalliance.org/fido2/', image:'https://images.unsplash.com/photo-1633265486064-086b219458ec?w=600&h=340&fit=crop' },
      { title:'URL Shorteners: The Hidden Danger in Your Inbox', summary:'Services like bit.ly hide the true destination of links. Learn how to safely expand shortened URLs before clicking and what tools can help.', date:'Jan 14, 2026', readTime:'5 min', category:'Security Tips', tags:['URL Shorteners','Link Safety'], link:'https://krebsonsecurity.com/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'How to Create Unbreakable Passwords in 2026', summary:'Password managers, passphrases, and entropy calculations. A practical guide to creating and managing strong, unique passwords for every account.', date:'Jan 3, 2026', readTime:'6 min', category:'Security Tips', tags:['Passwords','Password Manager','Security'], link:'https://www.nist.gov/publications', image:'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&h=340&fit=crop' },
      { title:'Securing Your Home Wi-Fi Against Attackers', summary:'Default router passwords, WPA2 vs WPA3, network segmentation, and guest networks. Harden your home network in 30 minutes.', date:'Dec 25, 2025', readTime:'6 min', category:'Security Tips', tags:['Wi-Fi','Router','Home Security'], link:'https://www.ncsc.gov.uk/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Browser Security Settings You Should Change Right Now', summary:'Enable strict site isolation, disable third-party cookies, review extension permissions, and configure DNS-over-HTTPS for safer browsing.', date:'Dec 18, 2025', readTime:'5 min', category:'Security Tips', tags:['Browser','Privacy','DNS-over-HTTPS'], link:'https://www.eff.org/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'How to Verify Email Sender Identity', summary:'Check SPF, DKIM, and DMARC headers to verify email authenticity. A step-by-step guide for spotting spoofed sender addresses.', date:'Dec 10, 2025', readTime:'7 min', category:'Security Tips', tags:['SPF','DKIM','DMARC','Email'], link:'https://www.proofpoint.com/', image:'https://images.unsplash.com/photo-1586769852044-692d6e3703f0?w=600&h=340&fit=crop' },
      { title:'Safe Online Shopping: Avoiding Fake Stores', summary:'Counterfeit e-commerce sites steal payment details. Learn to verify store legitimacy through WHOIS lookups, review analysis, and payment method safety.', date:'Dec 3, 2025', readTime:'5 min', category:'Security Tips', tags:['E-commerce','Online Shopping','Fraud'], link:'https://www.bbb.org/', image:'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=600&h=340&fit=crop' },
      { title:'What to Do If You\'ve Been Phished', summary:'Immediate steps after falling for a phishing attack: change passwords, enable MFA, check bank accounts, report the incident, and freeze your credit.', date:'Nov 25, 2025', readTime:'6 min', category:'Security Tips', tags:['Incident Response','Recovery','Tips'], link:'https://www.identitytheft.gov/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'Recognizing Fake Software Update Prompts', summary:'Malware often disguises itself as browser or system updates. Learn to distinguish genuine update notifications from malicious ones.', date:'Nov 18, 2025', readTime:'4 min', category:'Security Tips', tags:['Malware','Updates','Social Engineering'], link:'https://www.malwarebytes.com/', image:'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&h=340&fit=crop' },
      { title:'Setting Up a VPN: What You Need to Know', summary:'VPNs encrypt your traffic but aren\'t a silver bullet. Understand what VPNs do and don\'t protect, and how to choose a trustworthy provider.', date:'Nov 10, 2025', readTime:'7 min', category:'Security Tips', tags:['VPN','Privacy','Encryption'], link:'https://www.eff.org/', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'Digital Hygiene Checklist for 2026', summary:'Annual security review: update software, audit app permissions, review connected devices, check breach databases, and clean up old accounts.', date:'Nov 2, 2025', readTime:'5 min', category:'Security Tips', tags:['Digital Hygiene','Checklist','Annual Review'], link:'https://staysafeonline.org/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },

      // ─── Email Security (10) ───
      { title:'Email Security Best Practices for Remote Workers', summary:'Working from home increases phishing risk. Verify sender identities, spot spoofed emails, safely handle attachments, and configure your email client.', date:'Jan 27, 2026', readTime:'6 min', category:'Email Security', tags:['Remote Work','Best Practices','Email'], link:'https://www.ncsc.gov.uk/guidance/phishing', image:'https://images.unsplash.com/photo-1586769852044-692d6e3703f0?w=600&h=340&fit=crop' },
      { title:'Understanding DMARC, SPF, and DKIM', summary:'These email authentication protocols prevent spoofing but only when properly configured. A technical deep-dive into email authentication standards.', date:'Jan 10, 2026', readTime:'9 min', category:'Email Security', tags:['DMARC','SPF','DKIM','Authentication'], link:'https://dmarc.org/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Business Email Compromise: The $43 Billion Problem', summary:'BEC attacks caused $43B in losses globally. CEO fraud, vendor impersonation, and payroll diversion schemes explained with real case studies.', date:'Dec 28, 2025', readTime:'8 min', category:'Email Security', tags:['BEC','CEO Fraud','Wire Fraud'], link:'https://www.fbi.gov/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'Malicious Email Attachments: Beyond .exe Files', summary:'Modern malware hides in PDFs, Office macros, ISO images, and HTML files. Learn which file types are dangerous and how to safely handle attachments.', date:'Dec 15, 2025', readTime:'7 min', category:'Email Security', tags:['Attachments','Malware','File Types'], link:'https://www.virustotal.com/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'Email Header Analysis for Threat Detection', summary:'Reading email headers reveals the true origin, routing path, and authentication results of messages. A practical tutorial for security analysts.', date:'Dec 8, 2025', readTime:'10 min', category:'Email Security', tags:['Email Headers','Analysis','Forensics'], link:'https://mxtoolbox.com/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'Protecting Against Email Account Takeover', summary:'Compromised email accounts are used to send internal phishing. Implement conditional access policies, impossible travel detection, and session management.', date:'Nov 28, 2025', readTime:'7 min', category:'Email Security', tags:['Account Takeover','Conditional Access','Security'], link:'https://www.microsoft.com/en-us/security/blog/', image:'https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=600&h=340&fit=crop' },
      { title:'Email Encryption: PGP, S/MIME, and TLS Explained', summary:'End-to-end email encryption prevents interception. Compare PGP, S/MIME, and transport-layer encryption to choose the right solution for your needs.', date:'Nov 20, 2025', readTime:'8 min', category:'Email Security', tags:['Encryption','PGP','S/MIME','TLS'], link:'https://www.eff.org/', image:'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&h=340&fit=crop' },
      { title:'Configuring Microsoft 365 Anti-Phishing Policies', summary:'Step-by-step guide to setting up Safe Links, Safe Attachments, anti-spoofing, and impersonation protection in Microsoft Defender for Office 365.', date:'Nov 12, 2025', readTime:'10 min', category:'Email Security', tags:['Microsoft 365','Defender','Safe Links'], link:'https://learn.microsoft.com/en-us/microsoft-365/security/', image:'https://images.unsplash.com/photo-1633265486064-086b219458ec?w=600&h=340&fit=crop' },
      { title:'Google Workspace Email Security Features', summary:'Advanced phishing protection, attachment sandboxing, and anomalous activity detection in Google Workspace. Configuration guide for admins.', date:'Nov 5, 2025', readTime:'8 min', category:'Email Security', tags:['Google Workspace','Gmail','Admin'], link:'https://workspace.google.com/', image:'https://images.unsplash.com/photo-1553877522-43269d4ea984?w=600&h=340&fit=crop' },
      { title:'Email Security Gateways: Choosing the Right Solution', summary:'Compare Proofpoint, Mimecast, Barracuda, and Microsoft Defender. Key features, pricing considerations, and deployment architectures.', date:'Oct 28, 2025', readTime:'9 min', category:'Email Security', tags:['Email Gateway','Proofpoint','Mimecast'], link:'https://www.gartner.com/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },

      // ─── Enterprise (10) ───
      { title:'Enterprise Phishing Protection: Building a Security Culture', summary:'Technical controls alone aren\'t enough. Phishing simulation programs, awareness training, and incident response playbooks for organizations.', date:'Jan 17, 2026', readTime:'11 min', category:'Enterprise', tags:['Enterprise','Security Culture','Training'], link:'https://www.sans.org/', image:'https://images.unsplash.com/photo-1553877522-43269d4ea984?w=600&h=340&fit=crop' },
      { title:'Protecting Your Organization from Credential Harvesting', summary:'Credential harvesting uses cloned login pages on compromised sites. Detection strategies and defense-in-depth approaches for security teams.', date:'Jan 7, 2026', readTime:'8 min', category:'Enterprise', tags:['Credential Harvesting','Defense'], link:'https://attack.mitre.org/', image:'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&h=340&fit=crop' },
      { title:'Zero Trust Architecture for Phishing Defense', summary:'Never trust, always verify. Implementing zero trust principles eliminates implicit trust and limits the blast radius of successful phishing attacks.', date:'Dec 22, 2025', readTime:'10 min', category:'Enterprise', tags:['Zero Trust','Architecture','Network'], link:'https://www.nist.gov/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'SIEM Integration for Phishing Detection', summary:'Correlate email security alerts with endpoint, network, and identity data. Build detection rules that identify multi-stage phishing campaigns.', date:'Dec 10, 2025', readTime:'9 min', category:'Enterprise', tags:['SIEM','Detection','Correlation'], link:'https://www.splunk.com/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Phishing Simulation Programs That Actually Work', summary:'Design realistic phishing tests, measure click rates, provide instant training, and track improvement over time. Avoid common simulation mistakes.', date:'Nov 28, 2025', readTime:'8 min', category:'Enterprise', tags:['Simulation','Training','Metrics'], link:'https://www.knowbe4.com/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'Incident Response Plan for Phishing Attacks', summary:'Create, test, and refine your IR playbook for email-based attacks. Containment, eradication, recovery, and lessons learned workflows.', date:'Nov 18, 2025', readTime:'10 min', category:'Enterprise', tags:['Incident Response','Playbook','IR'], link:'https://www.sans.org/', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'SOC Analyst Guide to Email Threat Investigation', summary:'Triage phishing reports, analyze suspicious emails, investigate indicators of compromise, and automate response actions. A practical SOC workflow.', date:'Nov 8, 2025', readTime:'12 min', category:'Enterprise', tags:['SOC','Investigation','Triage'], link:'https://www.crowdstrike.com/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'Compliance Requirements for Email Security', summary:'Regulatory frameworks mandate specific email security controls. Map your phishing defenses to HIPAA, PCI DSS, SOX, and GDPR requirements.', date:'Oct 28, 2025', readTime:'9 min', category:'Enterprise', tags:['Compliance','HIPAA','PCI DSS','GDPR'], link:'https://www.hhs.gov/', image:'https://images.unsplash.com/photo-1589254065878-42c9da997008?w=600&h=340&fit=crop' },
      { title:'Managing Third-Party Phishing Risk', summary:'Vendors and partners can be the weakest link. Assess third-party email security posture and implement vendor risk management programs.', date:'Oct 18, 2025', readTime:'7 min', category:'Enterprise', tags:['Third-Party Risk','Vendor Management','Assessment'], link:'https://www.bitsight.com/', image:'https://images.unsplash.com/photo-1553877522-43269d4ea984?w=600&h=340&fit=crop' },
      { title:'Security Awareness Training ROI: Metrics That Matter', summary:'Measure the effectiveness of your security training program with meaningful KPIs beyond simple click rates. Cost-per-incident and risk reduction analysis.', date:'Oct 8, 2025', readTime:'7 min', category:'Enterprise', tags:['ROI','Metrics','Training','KPIs'], link:'https://www.sans.org/', image:'https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=600&h=340&fit=crop' },

      // ─── Case Studies (8) ───
      { title:'How a Fortune 500 Stopped a $2.3M BEC Attack', summary:'A sophisticated Business Email Compromise attack targeted a company\'s finance department with a spoofed CEO email. Multi-layer detection prevented the loss.', date:'Jan 24, 2026', readTime:'10 min', category:'Case Studies', tags:['BEC','Enterprise','Wire Fraud'], link:'https://www.fbi.gov/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'Hospital Ransomware Attack: Lessons from the Frontline', summary:'A regional hospital network was crippled by ransomware delivered through a phishing email. Timeline, response, and recovery strategies documented.', date:'Dec 18, 2025', readTime:'12 min', category:'Case Studies', tags:['Ransomware','Healthcare','Hospital'], link:'https://www.hhs.gov/', image:'https://images.unsplash.com/photo-1538108149393-fbbd81895907?w=600&h=340&fit=crop' },
      { title:'The SolarWinds Supply Chain Attack Dissected', summary:'How Russian state actors compromised 18,000 organizations through a software update. Technical analysis and timeline of the most impactful supply chain attack.', date:'Nov 25, 2025', readTime:'15 min', category:'Case Studies', tags:['SolarWinds','APT','Supply Chain'], link:'https://www.cisa.gov/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'Twitter Hack 2020: Social Engineering at Scale', summary:'How teenager hackers used phone-based social engineering to compromise Twitter\'s internal tools and hijack high-profile accounts for a Bitcoin scam.', date:'Nov 15, 2025', readTime:'9 min', category:'Case Studies', tags:['Social Engineering','Twitter','Insider Threat'], link:'https://krebsonsecurity.com/', image:'https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=600&h=340&fit=crop' },
      { title:'Ubiquiti Breach: When Employees Are the Target', summary:'Attackers impersonated Ubiquiti employees and gained access to cloud infrastructure. The ensuing cover-up attempt and whistleblower response analyzed.', date:'Nov 5, 2025', readTime:'8 min', category:'Case Studies', tags:['Ubiquiti','Insider','Cloud Security'], link:'https://www.darkreading.com/', image:'https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=600&h=340&fit=crop' },
      { title:'Colonial Pipeline: How Phishing Led to a National Emergency', summary:'A single compromised password led to the shutdown of the largest fuel pipeline in the US. Attack chain analysis and critical infrastructure lessons.', date:'Oct 25, 2025', readTime:'11 min', category:'Case Studies', tags:['Colonial Pipeline','Critical Infrastructure','Ransomware'], link:'https://www.cisa.gov/', image:'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&h=340&fit=crop' },
      { title:'MGM Resorts Hack: Social Engineering Beats Billions', summary:'A simple phone call to the help desk brought down a $14B casino empire. The Scattered Spider group\'s attack chain and MGM\'s $100M recovery cost.', date:'Oct 15, 2025', readTime:'10 min', category:'Case Studies', tags:['MGM','Social Engineering','Help Desk'], link:'https://www.bleepingcomputer.com/', image:'https://images.unsplash.com/photo-1534536281715-e28d76689b4d?w=600&h=340&fit=crop' },
      { title:'Microsoft Exchange ProxyLogon: Mass Exploitation Timeline', summary:'Zero-day vulnerabilities in Exchange Server were exploited by multiple threat groups. Technical details, patch timeline, and lessons for on-prem infrastructure.', date:'Oct 5, 2025', readTime:'13 min', category:'Case Studies', tags:['Exchange','Zero-Day','ProxyLogon'], link:'https://www.microsoft.com/en-us/security/blog/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },

      // ─── Privacy & Data (10) ───
      { title:'Your Digital Footprint: What Hackers Know About You', summary:'OSINT tools reveal your email, phone, employer, location, and social connections. Understand your digital exposure and how to minimize it.', date:'Feb 1, 2026', readTime:'7 min', category:'Privacy & Data', tags:['OSINT','Privacy','Digital Footprint'], link:'https://www.eff.org/', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'Data Brokers: Who\'s Selling Your Personal Information', summary:'Hundreds of companies collect and sell your data. Learn which data brokers have your information and how to request deletion under privacy laws.', date:'Jan 18, 2026', readTime:'6 min', category:'Privacy & Data', tags:['Data Brokers','Privacy','GDPR'], link:'https://www.privacyrights.org/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'GDPR and Phishing: Your Rights as a Victim', summary:'If your data was exposed through a phishing attack on a company, GDPR gives you specific rights. Learn how to file complaints and seek compensation.', date:'Dec 22, 2025', readTime:'6 min', category:'Privacy & Data', tags:['GDPR','Rights','Data Protection'], link:'https://gdpr.eu/', image:'https://images.unsplash.com/photo-1589254065878-42c9da997008?w=600&h=340&fit=crop' },
      { title:'End-to-End Encryption: Messengers Compared', summary:'Signal, WhatsApp, Telegram, and iMessage compared on encryption strength, metadata privacy, and security defaults for everyday communication.', date:'Dec 12, 2025', readTime:'7 min', category:'Privacy & Data', tags:['Encryption','Messaging','Signal','WhatsApp'], link:'https://signal.org/', image:'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&h=340&fit=crop' },
      { title:'Cookie Tracking and Online Privacy in 2026', summary:'Third-party cookies are dying, but fingerprinting and first-party tracking remain. Navigate the changing privacy landscape and protect your browsing.', date:'Dec 1, 2025', readTime:'5 min', category:'Privacy & Data', tags:['Cookies','Tracking','Fingerprinting'], link:'https://www.eff.org/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'Identity Theft Prevention: A Complete Guide', summary:'Monitor your credit, freeze accounts, use identity theft protection services, and know the warning signs. Comprehensive identity protection strategies.', date:'Nov 22, 2025', readTime:'8 min', category:'Privacy & Data', tags:['Identity Theft','Credit Freeze','Monitoring'], link:'https://www.identitytheft.gov/', image:'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=600&h=340&fit=crop' },
      { title:'Privacy-Focused Alternatives to Big Tech Services', summary:'Replace Google, Microsoft, and Facebook with privacy-respecting alternatives. Email, search, cloud storage, and social media options reviewed.', date:'Nov 12, 2025', readTime:'7 min', category:'Privacy & Data', tags:['Privacy','Alternatives','Big Tech'], link:'https://privacytools.io/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'The Right to Be Forgotten: Removing Your Data Online', summary:'GDPR, CCPA, and other laws give you the right to request data deletion. Practical steps to remove your information from websites and search engines.', date:'Nov 2, 2025', readTime:'6 min', category:'Privacy & Data', tags:['Data Deletion','CCPA','Right to Erasure'], link:'https://support.google.com/', image:'https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=600&h=340&fit=crop' },
      { title:'Dark Web Monitoring: Is Your Data Already Compromised?', summary:'Leaked credentials, personal data, and financial information are traded on dark web forums. Tools and services that monitor your exposure.', date:'Oct 22, 2025', readTime:'6 min', category:'Privacy & Data', tags:['Dark Web','Monitoring','Data Breach'], link:'https://haveibeenpwned.com/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'Children\'s Online Privacy: COPPA and Beyond', summary:'Protecting children from online threats requires parental controls, privacy-safe platforms, and age-appropriate security education.', date:'Oct 12, 2025', readTime:'7 min', category:'Privacy & Data', tags:['COPPA','Children','Parental Controls'], link:'https://www.ftc.gov/', image:'https://images.unsplash.com/photo-1534536281715-e28d76689b4d?w=600&h=340&fit=crop' },

      // ─── Malware (10) ───
      { title:'Ransomware in 2026: Evolution of Double Extortion', summary:'Modern ransomware gangs encrypt data AND threaten to leak it. Understand the ransomware ecosystem, negotiation tactics, and defense strategies.', date:'Feb 7, 2026', readTime:'9 min', category:'Malware', tags:['Ransomware','Double Extortion','Recovery'], link:'https://www.nomoreransom.org/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'Emotet: The Malware That Won\'t Die', summary:'Emotet continues to evolve after multiple takedown attempts. Its modular architecture and delivery methods make it one of the most persistent threats.', date:'Jan 22, 2026', readTime:'8 min', category:'Malware', tags:['Emotet','Botnet','Modular Malware'], link:'https://www.europol.europa.eu/', image:'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=600&h=340&fit=crop' },
      { title:'Keyloggers: How They Work and How to Detect Them', summary:'Software and hardware keyloggers capture every keystroke. Detection methods, prevention strategies, and why password managers help defeat them.', date:'Jan 8, 2026', readTime:'6 min', category:'Malware', tags:['Keylogger','Detection','Prevention'], link:'https://www.malwarebytes.com/', image:'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&h=340&fit=crop' },
      { title:'Fileless Malware: Attacks That Leave No Trace', summary:'Living-off-the-land attacks use PowerShell, WMI, and legitimate system tools. Traditional antivirus can\'t detect them. Learn behavioral detection approaches.', date:'Dec 28, 2025', readTime:'8 min', category:'Malware', tags:['Fileless','LOLBins','PowerShell'], link:'https://www.crowdstrike.com/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'Infostealers: The Silent Data Thieves', summary:'Redline, Raccoon, and Vidar steal browser passwords, cookies, crypto wallets, and session tokens. How these cheap malware-as-a-service tools operate.', date:'Dec 15, 2025', readTime:'7 min', category:'Malware', tags:['Infostealer','Redline','MaaS'], link:'https://www.welivesecurity.com/', image:'https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=600&h=340&fit=crop' },
      { title:'Rootkits: Invisible Malware Deep in Your System', summary:'Kernel-level and bootkit rootkits persist below the operating system. Detection requires specialized tools and techniques beyond standard antivirus.', date:'Dec 5, 2025', readTime:'9 min', category:'Malware', tags:['Rootkit','Kernel','Bootkit'], link:'https://www.kaspersky.com/', image:'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&h=340&fit=crop' },
      { title:'Cryptojacking: When Your CPU Mines for Criminals', summary:'Malicious cryptocurrency mining runs silently on infected devices, consuming power and degrading performance. Browser-based and file-based variants explained.', date:'Nov 25, 2025', readTime:'5 min', category:'Malware', tags:['Cryptojacking','Cryptocurrency','Mining'], link:'https://krebsonsecurity.com/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'RATs: Complete Control From Afar', summary:'Remote Access Trojans give attackers full control of infected machines. Camera, microphone, file system, and keystrokes — all accessible remotely.', date:'Nov 15, 2025', readTime:'7 min', category:'Malware', tags:['RAT','Remote Access','Trojan'], link:'https://www.darkreading.com/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Wiper Malware: Destruction as the Goal', summary:'Unlike ransomware, wiper malware aims to destroy data permanently. NotPetya, HermeticWiper, and other destructive tools used in geopolitical conflicts.', date:'Nov 5, 2025', readTime:'8 min', category:'Malware', tags:['Wiper','NotPetya','Destructive'], link:'https://www.cisa.gov/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'Polymorphic Malware: Evading Signature Detection', summary:'Malware that changes its code with every execution defeats traditional antivirus signatures. Heuristic and behavioral analysis are the countermeasures.', date:'Oct 25, 2025', readTime:'8 min', category:'Malware', tags:['Polymorphic','Evasion','Detection'], link:'https://www.virustotal.com/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },

      // ─── Social Engineering (10) ───
      { title:'The Psychology Behind Social Engineering Attacks', summary:'Urgency, authority, social proof, and reciprocity — psychological principles that make social engineering effective. Understanding the science helps build resistance.', date:'Feb 4, 2026', readTime:'8 min', category:'Social Engineering', tags:['Psychology','Manipulation','Awareness'], link:'https://www.social-engineer.org/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },
      { title:'Pretexting: Crafting Convincing Cover Stories', summary:'Attackers create elaborate backstories to manipulate victims. From fake IT support calls to impersonating delivery drivers, pretexting is an art form.', date:'Jan 25, 2026', readTime:'6 min', category:'Social Engineering', tags:['Pretexting','Impersonation','Cover Story'], link:'https://www.social-engineer.org/', image:'https://images.unsplash.com/photo-1534536281715-e28d76689b4d?w=600&h=340&fit=crop' },
      { title:'Tailgating and Physical Social Engineering', summary:'Following employees through secure doors, impersonating maintenance workers, and planting USB drives. Physical security breaches complement cyber attacks.', date:'Jan 12, 2026', readTime:'5 min', category:'Social Engineering', tags:['Tailgating','Physical Security','USB Drop'], link:'https://www.sans.org/', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'Baiting Attacks: Free USB Drives and Malicious Downloads', summary:'Leaving malware-laden USB drives in parking lots still works. Digital baiting through free software downloads and pirated content is even more effective.', date:'Dec 28, 2025', readTime:'5 min', category:'Social Engineering', tags:['Baiting','USB','Downloads'], link:'https://www.malwarebytes.com/', image:'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=600&h=340&fit=crop' },
      { title:'Watering Hole Attacks: Poisoning Trusted Websites', summary:'Attackers compromise websites frequently visited by target organizations. Visitors get infected without clicking suspicious links or opening emails.', date:'Dec 18, 2025', readTime:'7 min', category:'Social Engineering', tags:['Watering Hole','Compromise','Drive-by'], link:'https://www.crowdstrike.com/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'Romance Scams and Emotional Manipulation Online', summary:'Criminals invest months building romantic relationships before requesting money. The emotional exploitation causes billions in losses annually worldwide.', date:'Dec 8, 2025', readTime:'6 min', category:'Social Engineering', tags:['Romance Scam','Emotional Exploitation','Fraud'], link:'https://www.fbi.gov/', image:'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&h=340&fit=crop' },
      { title:'Tech Support Scams: The Persistent Fraud', summary:'Fake virus warnings and cold calls trick victims into paying for unnecessary support. The tech support scam playbook and how to fight back.', date:'Nov 28, 2025', readTime:'5 min', category:'Social Engineering', tags:['Tech Support','Scam','Cold Call'], link:'https://www.ftc.gov/', image:'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&h=340&fit=crop' },
      { title:'Authority Exploitation: Why We Obey Fake Bosses', summary:'Emails from "the CEO" or "the IRS" trigger automatic compliance. Understanding authority bias helps employees question unusual requests from senior figures.', date:'Nov 18, 2025', readTime:'6 min', category:'Social Engineering', tags:['Authority','Bias','CEO Fraud'], link:'https://www.social-engineer.org/', image:'https://images.unsplash.com/photo-1553877522-43269d4ea984?w=600&h=340&fit=crop' },
      { title:'Disinformation Campaigns and Phishing Synergy', summary:'State actors combine disinformation with phishing to amplify impact. Fake news sites, social media bots, and targeted credential theft work together.', date:'Nov 8, 2025', readTime:'9 min', category:'Social Engineering', tags:['Disinformation','State Actors','Hybrid Threat'], link:'https://www.europol.europa.eu/', image:'https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=600&h=340&fit=crop' },
      { title:'Social Engineering Red Team Assessments', summary:'Hire professionals to test your organization with real-world social engineering attacks. Methodology, rules of engagement, and reporting best practices.', date:'Oct 28, 2025', readTime:'8 min', category:'Social Engineering', tags:['Red Team','Assessment','Penetration Testing'], link:'https://www.offensive-security.com/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },

      // ─── Mobile Security (10) ───
      { title:'Mobile Phishing: Why Your Phone Is the New Target', summary:'60% of phishing attacks now target mobile devices. Smaller screens, hidden URLs, and app-based vectors make mobile phishing harder to detect.', date:'Feb 3, 2026', readTime:'6 min', category:'Mobile Security', tags:['Mobile','Phishing','Smartphone'], link:'https://www.lookout.com/', image:'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&h=340&fit=crop' },
      { title:'Malicious Apps: Threats Hiding in App Stores', summary:'Fake apps in Google Play and third-party stores steal data and credentials. Review permissions, check developer reputation, and spot copycats.', date:'Jan 16, 2026', readTime:'6 min', category:'Mobile Security', tags:['Malicious Apps','Google Play','Permissions'], link:'https://www.lookout.com/', image:'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=600&h=340&fit=crop' },
      { title:'SIM Swapping: Hijacking Your Phone Number', summary:'Attackers convince carriers to transfer your number to their SIM. This bypasses SMS-based 2FA and gives access to banking and email accounts.', date:'Jan 4, 2026', readTime:'7 min', category:'Mobile Security', tags:['SIM Swap','Phone Number','2FA Bypass'], link:'https://krebsonsecurity.com/', image:'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&h=340&fit=crop' },
      { title:'Mobile Device Management for Enterprise Security', summary:'MDM solutions enforce security policies, remotely wipe lost devices, and control app installations. Comparing Intune, Jamf, and VMware Workspace ONE.', date:'Dec 20, 2025', readTime:'9 min', category:'Mobile Security', tags:['MDM','Enterprise','Intune','Jamf'], link:'https://learn.microsoft.com/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'iOS vs Android Security: An Objective Comparison', summary:'App sandboxing, update policies, permission models, and encryption implementations compared. Neither platform is perfect — know the trade-offs.', date:'Dec 8, 2025', readTime:'8 min', category:'Mobile Security', tags:['iOS','Android','Comparison'], link:'https://support.apple.com/', image:'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=600&h=340&fit=crop' },
      { title:'Public Wi-Fi Attacks: Coffee Shop Hacking', summary:'Man-in-the-middle attacks, evil twin access points, and SSL stripping at coffee shops and airports. Stay safe on public networks.', date:'Nov 28, 2025', readTime:'5 min', category:'Mobile Security', tags:['Public Wi-Fi','MITM','Evil Twin'], link:'https://www.eff.org/', image:'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&h=340&fit=crop' },
      { title:'Pegasus Spyware: What Everyone Should Know', summary:'NSO Group\'s Pegasus exploits zero-click vulnerabilities to silently surveil smartphones. Implications for journalists, activists, and everyday users.', date:'Nov 18, 2025', readTime:'8 min', category:'Mobile Security', tags:['Pegasus','Spyware','Zero-Click'], link:'https://citizenlab.ca/', image:'https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=600&h=340&fit=crop' },
      { title:'Bluetooth Vulnerabilities and Smartphone Security', summary:'BlueBorne, KNOB, and BrakTooth vulnerabilities allow attackers within Bluetooth range to exploit devices. Mitigation strategies for users.', date:'Nov 8, 2025', readTime:'6 min', category:'Mobile Security', tags:['Bluetooth','BlueBorne','Wireless'], link:'https://www.armis.com/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Mobile Banking Security: Protecting Your Financial Apps', summary:'Biometric authentication, enrollment security, jailbreak detection, and secure enclave usage. How banks protect mobile transactions and what you should verify.', date:'Oct 28, 2025', readTime:'7 min', category:'Mobile Security', tags:['Banking','Financial','Biometric'], link:'https://www.fdic.gov/', image:'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=600&h=340&fit=crop' },
      { title:'Securing Your Kids\' Smartphones', summary:'Parental controls, content filtering, location sharing, and age-appropriate privacy settings. A practical guide for parents managing children\'s mobile devices.', date:'Oct 18, 2025', readTime:'6 min', category:'Mobile Security', tags:['Kids','Parental Controls','Family'], link:'https://www.commonsensemedia.org/', image:'https://images.unsplash.com/photo-1534536281715-e28d76689b4d?w=600&h=340&fit=crop' },

      // ─── AI & ML Security (8) ───
      { title:'AI-Powered Phishing: ChatGPT in the Wrong Hands', summary:'Large language models generate convincing phishing emails without grammatical errors. How AI is changing the phishing landscape and what defenders can do.', date:'Feb 6, 2026', readTime:'8 min', category:'AI & ML Security', tags:['AI','ChatGPT','LLM','Phishing'], link:'https://openai.com/', image:'https://images.unsplash.com/photo-1677442136019-21780ecad995?w=600&h=340&fit=crop' },
      { title:'Machine Learning Models for URL Classification', summary:'Feature engineering, model architectures, and training data requirements for building effective phishing URL classifiers. A technical overview.', date:'Jan 22, 2026', readTime:'10 min', category:'AI & ML Security', tags:['ML','URL Classification','NLP'], link:'https://research.google/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'Adversarial Attacks on Phishing Detection Models', summary:'Attackers can craft URLs and content specifically designed to fool ML classifiers. Understanding adversarial ML helps build more robust detection systems.', date:'Jan 8, 2026', readTime:'9 min', category:'AI & ML Security', tags:['Adversarial ML','Evasion','Robustness'], link:'https://arxiv.org/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'Natural Language Processing for Email Threat Detection', summary:'NLP models analyze email tone, urgency cues, and impersonation patterns. Transformer architectures outperform traditional keyword-based filters.', date:'Dec 20, 2025', readTime:'8 min', category:'AI & ML Security', tags:['NLP','Email','Transformers'], link:'https://huggingface.co/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'Computer Vision for Phishing Page Detection', summary:'Image similarity algorithms detect cloned login pages by comparing visual appearance to legitimate sites. CNN-based approaches achieve 98%+ accuracy.', date:'Dec 5, 2025', readTime:'7 min', category:'AI & ML Security', tags:['Computer Vision','CNN','Image Analysis'], link:'https://research.google/', image:'https://images.unsplash.com/photo-1589254065878-42c9da997008?w=600&h=340&fit=crop' },
      { title:'Deepfakes in Phishing: Video and Audio Manipulation', summary:'AI-generated deepfake videos and voice clones impersonate executives in video calls. The technology is democratizing and getting cheaper every month.', date:'Nov 18, 2025', readTime:'7 min', category:'AI & ML Security', tags:['Deepfake','Video','Audio','Impersonation'], link:'https://www.darkreading.com/', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'Federated Learning for Privacy-Preserving Security', summary:'Train ML models across organizations without sharing sensitive data. Federated learning enables collaborative phishing detection while maintaining privacy.', date:'Nov 2, 2025', readTime:'9 min', category:'AI & ML Security', tags:['Federated Learning','Privacy','Collaboration'], link:'https://ai.google/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'Explainable AI in Cybersecurity Decision Making', summary:'Black-box ML models need interpretability for security teams to trust their decisions. SHAP, LIME, and attention visualization for phishing classifiers.', date:'Oct 15, 2025', readTime:'8 min', category:'AI & ML Security', tags:['XAI','Explainability','SHAP','LIME'], link:'https://arxiv.org/', image:'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=600&h=340&fit=crop' },

      // ─── Cloud Security (10) ───
      { title:'Cloud Phishing: Abusing Trusted Services', summary:'Attackers host phishing pages on Azure, AWS, Google Cloud, and Firebase. Trusted domains bypass URL filters. Detection requires cloud-aware security.', date:'Feb 2, 2026', readTime:'7 min', category:'Cloud Security', tags:['Cloud','Azure','AWS','Hosting'], link:'https://www.paloaltonetworks.com/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'OAuth Consent Phishing: Stealing Access Without Passwords', summary:'Malicious OAuth apps request permissions to read email and files. Victims grant access through legitimate login flows, bypassing all password protections.', date:'Jan 18, 2026', readTime:'8 min', category:'Cloud Security', tags:['OAuth','Consent Phishing','API Security'], link:'https://www.microsoft.com/en-us/security/blog/', image:'https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?w=600&h=340&fit=crop' },
      { title:'Securing AWS S3 Buckets: Preventing Data Exposure', summary:'Misconfigured S3 buckets expose sensitive data publicly. Learn IAM policies, bucket policies, access logging, and automated compliance scanning.', date:'Jan 2, 2026', readTime:'8 min', category:'Cloud Security', tags:['AWS','S3','IAM','Configuration'], link:'https://aws.amazon.com/s3/', image:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=340&fit=crop' },
      { title:'Azure Active Directory Security Best Practices', summary:'Conditional access, PIM, risk-based authentication, and tenant hardening. Protect your Azure AD from credential attacks and unauthorized access.', date:'Dec 18, 2025', readTime:'10 min', category:'Cloud Security', tags:['Azure AD','Conditional Access','PIM'], link:'https://learn.microsoft.com/', image:'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&h=340&fit=crop' },
      { title:'Google Cloud Security Command Center Overview', summary:'Unified security management across Google Cloud services. Asset discovery, vulnerability scanning, and threat detection capabilities explained.', date:'Dec 5, 2025', readTime:'7 min', category:'Cloud Security', tags:['Google Cloud','SCC','CSPM'], link:'https://cloud.google.com/', image:'https://images.unsplash.com/photo-1553877522-43269d4ea984?w=600&h=340&fit=crop' },
      { title:'Container Security: Docker and Kubernetes Threats', summary:'Container escape vulnerabilities, image poisoning, and Kubernetes RBAC misconfigurations. Secure your container orchestration from deployment to runtime.', date:'Nov 22, 2025', readTime:'9 min', category:'Cloud Security', tags:['Docker','Kubernetes','Containers'], link:'https://kubernetes.io/', image:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&h=340&fit=crop' },
      { title:'Serverless Security: Lambda and Azure Functions Risks', summary:'Function event injection, insecure dependencies, and excessive permissions in serverless architectures. Security considerations for FaaS deployments.', date:'Nov 10, 2025', readTime:'7 min', category:'Cloud Security', tags:['Serverless','Lambda','Azure Functions'], link:'https://aws.amazon.com/lambda/', image:'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&h=340&fit=crop' },
      { title:'Cloud Access Security Brokers (CASB) Explained', summary:'CASBs provide visibility, compliance, data security, and threat protection for cloud services. Compare McAfee MVISION, Netskope, and Zscaler.', date:'Oct 28, 2025', readTime:'8 min', category:'Cloud Security', tags:['CASB','Cloud Security','SaaS'], link:'https://www.gartner.com/', image:'https://images.unsplash.com/photo-1563986768609-322da13575f2?w=600&h=340&fit=crop' },
      { title:'Multi-Cloud Security Strategy: Challenges and Solutions', summary:'Managing security across AWS, Azure, and GCP simultaneously. Unified monitoring, consistent policies, and cross-cloud identity management.', date:'Oct 15, 2025', readTime:'9 min', category:'Cloud Security', tags:['Multi-Cloud','Strategy','Management'], link:'https://www.paloaltonetworks.com/', image:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=600&h=340&fit=crop' },
      { title:'Infrastructure as Code Security Scanning', summary:'Detect misconfigurations in Terraform, CloudFormation, and ARM templates before deployment. Shift-left security for cloud infrastructure.', date:'Oct 5, 2025', readTime:'7 min', category:'Cloud Security', tags:['IaC','Terraform','Shift-Left'], link:'https://www.checkov.io/', image:'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&h=340&fit=crop' },
    ];
  }
}

// Initialize
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() { window.blogSystem = new BlogSystem(); });
} else {
  window.blogSystem = new BlogSystem();
}
