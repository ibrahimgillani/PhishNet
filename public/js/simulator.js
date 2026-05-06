document.addEventListener('DOMContentLoaded', () => {
  // --- Email Dataset ---
  const emails = [
    {
      senderName: 'CEO - John Smith',
      senderEmail: 'john.smith.executive@gmail.com',
      avatar: 'J',
      subject: 'URGENT: Need Apple Gift Cards immediately',
      body: `
        <p>Are you at your desk right now?</p>
        <p>I am stuck in a meeting with a client and I need you to purchase 5 Apple Gift Cards ($100 each) to send to them as a corporate gift. I cannot make calls right now.</p>
        <p>Please purchase them and email me the codes immediately. I will reimburse you by the end of the day.</p>
        <p>Thanks,<br>John Smith<br>CEO</p>
      `,
      isPhishing: true,
      explanation: '<strong>Look at the sender email!</strong> The CEO of a company would not use a generic "@gmail.com" address for urgent business. Scammers use urgency and unusual requests (like gift cards) to bypass your critical thinking.'
    },
    {
      senderName: 'GitHub',
      senderEmail: 'noreply@github.com',
      avatar: 'G',
      subject: '[GitHub] A new public key was added to your account',
      body: `
        <p>Hey there,</p>
        <p>A new public key was added to your account from the IP address <strong>192.168.1.45</strong>.</p>
        <p>If you did not make this change, please visit <a href="#" style="color:#0B63D9;">https://github.com/settings/keys</a> immediately to review your security settings.</p>
        <p>Thanks,<br>The GitHub Security Team</p>
      `,
      isPhishing: false,
      explanation: '<strong>This is a legitimate security alert.</strong> The sender domain is exactly "github.com", and the link provided points to the actual GitHub website without any suspicious subdomains or typos.'
    },
    {
      senderName: 'PayPal Security',
      senderEmail: 'support@paypal-secure-update.com',
      avatar: 'P',
      subject: 'Action Required: Your account has been temporarily restricted',
      body: `
        <p>Dear Customer,</p>
        <p>We noticed unusual activity on your PayPal account. For your security, we have temporarily restricted your account features.</p>
        <p>Please click the button below to verify your identity and restore full access.</p>
        <div style="margin: 20px 0;">
          <a href="#" style="background:#003087; color:white; padding:10px 20px; text-decoration:none; border-radius:4px; font-weight:bold;">Verify Account Now</a>
        </div>
        <p>If you do not verify your account within 24 hours, it will be permanently closed.</p>
      `,
      isPhishing: true,
      explanation: '<strong>Look at the sender domain!</strong> "paypal-secure-update.com" is a typosquatting domain designed to look like PayPal. A real email from PayPal will always come from "paypal.com" and address you by your real name, not "Dear Customer".'
    },
    {
      senderName: 'Netflix',
      senderEmail: 'info@mailer.netflix.com',
      avatar: 'N',
      subject: 'Your subscription is renewing soon',
      body: `
        <p>Hi Ibrahim,</p>
        <p>We hope you're enjoying your Netflix subscription. Just a quick reminder that your Premium plan will automatically renew on May 5th, 2026.</p>
        <p>Your card ending in <strong>4912</strong> will be charged $19.99.</p>
        <p>If you need to make any changes to your plan, you can do so in your <a href="#" style="color:#E50914;">Account Settings</a>.</p>
        <p>Enjoy watching!</p>
      `,
      isPhishing: false,
      explanation: '<strong>This is a safe billing reminder.</strong> It uses your actual name, references specific partial payment details, and comes from a verified subdomain (mailer.netflix.com). It lacks the aggressive urgency usually found in scams.'
    },
    {
      senderName: 'IT Support Desk',
      senderEmail: 'admin@it-portal-auth.web.app',
      avatar: 'I',
      subject: 'MANDATORY: Quarterly Password Reset',
      body: `
        <p>All Employees,</p>
        <p>As part of our new quarterly security compliance policy, all employees must reset their network passwords before 5:00 PM today.</p>
        <p>Failure to update your password will result in an immediate lock-out from Microsoft 365, Slack, and the internal VPN.</p>
        <p>Click here to reset your password: <br>
        <a href="#" style="color:#0B63D9;">https://internal-sso.auth-login.com/reset</a></p>
        <p>IT Department</p>
      `,
      isPhishing: true,
      explanation: '<strong>Fake IT Scam!</strong> The sender is using a free hosting domain (".web.app"), and the link points to a sketchy domain ("auth-login.com") instead of your company portal. The extreme threat of immediate lock-out is a classic manipulation tactic.'
    }
  ];

  let currentIndex = 0;
  let correctGuesses = 0;

  // --- UI Elements ---
  const simSenderName = document.getElementById('sim-sender-name');
  const simSenderEmail = document.getElementById('sim-sender-email');
  const simAvatar = document.getElementById('sim-avatar');
  const simSubject = document.getElementById('sim-subject');
  const simBody = document.getElementById('sim-body');
  
  const btnSafe = document.getElementById('btn-safe');
  const btnPhishing = document.getElementById('btn-phishing');
  
  const resultOverlay = document.getElementById('sim-result-overlay');
  const resultCard = document.getElementById('sim-result-card');
  const resultIcon = document.getElementById('sim-result-icon');
  const resultTitle = document.getElementById('sim-result-title');
  const resultBadge = document.getElementById('sim-result-badge');
  const resultExplanation = document.getElementById('sim-result-explanation');
  const btnNext = document.getElementById('btn-next');

  const progressBar = document.getElementById('sim-progress');
  const progressText = document.getElementById('sim-progress-text');

  const gameView = document.getElementById('sim-game-view');
  const finalView = document.getElementById('sim-final-view');
  
  // --- Functions ---
  function loadEmail(index) {
    if (index >= emails.length) {
      showFinalScore();
      return;
    }
    const email = emails[index];
    simSenderName.textContent = email.senderName;
    simSenderEmail.textContent = email.senderEmail;
    simAvatar.textContent = email.avatar;
    simSubject.textContent = email.subject;
    simBody.innerHTML = email.body;

    // Update Progress
    progressBar.style.width = `${(index / emails.length) * 100}%`;
    progressText.textContent = `Email ${index + 1} of ${emails.length}`;
  }

  function handleGuess(userGuessedSafe) {
    const email = emails[currentIndex];
    const isActuallySafe = !email.isPhishing;
    const isCorrect = (userGuessedSafe === isActuallySafe);

    if (isCorrect) correctGuesses++;

    showResult(isCorrect, email);
  }

  function showResult(isCorrect, email) {
    resultOverlay.classList.add('active');
    
    // Clear old classes
    resultCard.className = 'sim-result-card';
    
    if (isCorrect) {
      resultCard.classList.add('correct');
      resultIcon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4 12 14.01l-3-3"/></svg>';
      resultTitle.textContent = 'Correct!';
    } else {
      resultCard.classList.add('incorrect');
      resultIcon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
      resultTitle.textContent = 'Incorrect!';
    }

    resultBadge.textContent = email.isPhishing ? 'This was a Phishing attempt' : 'This was a Safe email';
    resultBadge.style.backgroundColor = email.isPhishing ? 'rgba(255, 77, 77, 0.15)' : 'rgba(0, 255, 136, 0.15)';
    resultBadge.style.color = email.isPhishing ? '#ff4d4d' : '#00ff88';

    resultExplanation.innerHTML = email.explanation;

    if (currentIndex === emails.length - 1) {
      btnNext.textContent = 'See Final Score';
    } else {
      btnNext.textContent = 'Next Email';
    }
  }

  function showFinalScore() {
    gameView.style.display = 'none';
    document.querySelector('.simulator-header').style.display = 'none';
    finalView.style.display = 'block';

    const percentage = Math.round((correctGuesses / emails.length) * 100);
    document.getElementById('sim-score-text').textContent = `${percentage}%`;
    document.getElementById('sim-score-path').setAttribute('stroke-dasharray', `${percentage}, 100`);

    const rankEl = document.getElementById('sim-rank');
    if (percentage === 100) {
      rankEl.textContent = 'Cyber Security Master 🏆';
      rankEl.style.color = '#00ff88';
      document.getElementById('sim-score-path').style.stroke = '#00ff88';
    } else if (percentage >= 80) {
      rankEl.textContent = 'Advanced Defender 🛡️';
      rankEl.style.color = '#0B63D9';
      document.getElementById('sim-score-path').style.stroke = '#0B63D9';
    } else if (percentage >= 60) {
      rankEl.textContent = 'Cyber Rookie 🔰';
      rankEl.style.color = '#fbbf24';
      document.getElementById('sim-score-path').style.stroke = '#fbbf24';
    } else {
      rankEl.textContent = 'Easy Target 🎯';
      rankEl.style.color = '#ff4d4d';
      document.getElementById('sim-score-path').style.stroke = '#ff4d4d';
    }

    document.getElementById('sim-final-desc').textContent = `You correctly identified ${correctGuesses} out of ${emails.length} emails.`;
  }

  // --- Event Listeners ---
  btnSafe.addEventListener('click', () => handleGuess(true));
  btnPhishing.addEventListener('click', () => handleGuess(false));

  btnNext.addEventListener('click', () => {
    resultOverlay.classList.remove('active');
    currentIndex++;
    loadEmail(currentIndex);
  });

  document.getElementById('btn-retry').addEventListener('click', () => {
    currentIndex = 0;
    correctGuesses = 0;
    finalView.style.display = 'none';
    document.querySelector('.simulator-header').style.display = 'block';
    gameView.style.display = 'block';
    loadEmail(currentIndex);
  });

  // Init
  loadEmail(currentIndex);
});
