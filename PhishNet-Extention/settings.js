// PhishNet Extension - Settings Page JavaScript
// Wrapped to avoid redeclaration when the script is injected multiple times
(function () {
if (window.__PHISHNET_SETTINGS_LOADED) {
    console.log('settings.js already loaded; skipping re-init');
    return;
}
window.__PHISHNET_SETTINGS_LOADED = true;

console.log('📄 settings.js loaded!');

// Flag controlled by popup.js; use window-scoped to avoid re-declaration errors if script loads twice
if (typeof window.USE_SETTINGS_API === 'undefined') {
    window.USE_SETTINGS_API = window.__PHISHNET_USE_SETTINGS_API === true;
}
var USE_SETTINGS_API = window.USE_SETTINGS_API;

// Pre-register init hooks so popup.js can find them even before bottom-of-file assignment
window.settingsPageInit = window.settingsPageInit || function () { return initializeSettingsPage(); };
window.initializeSettingsPage = window.initializeSettingsPage || initializeSettingsPage;

// Use page references exposed by popup.js
const { settingsPage, dashboardPage } = window.__phishnetPages || {};

// Back button (local reference)
const settingsBackBtn = document.getElementById('settings-back-btn');

// Profile Elements
const profilePictureInput = document.getElementById('profile-picture-input');
const profilePictureBtn = document.getElementById('profile-picture-btn');
const profilePicture = document.getElementById('profile-picture');
const profileNameInput = document.getElementById('profile-name');
const profileEmailInput = document.getElementById('profile-email');
const profileSaveBtn = document.getElementById('profile-save-btn');

// Cropper Elements
const cropperModal = document.getElementById('cropper-modal');
const cropperImage = document.getElementById('cropper-image');
const cropperStage = document.getElementById('cropper-stage');
const cropperZoom = document.getElementById('cropper-zoom');
const cropperApplyBtn = document.getElementById('cropper-apply');
const cropperCancelBtn = document.getElementById('cropper-cancel');

// Scanning Settings
const scanUrlsToggle = document.getElementById('scan-urls-toggle-page');
const scanEmailsToggle = document.getElementById('scan-emails-toggle-page');
const realTimeProtectionToggle = document.getElementById('real-time-protection-toggle');

// Privacy Settings
const dataSharingToggle = document.getElementById('data-sharing-toggle-page');
const autoSubmitToggle = document.getElementById('auto-submit-toggle-page');

// Notification Settings
const notifyToggle = document.getElementById('notify-toggle-page');
const emailAlertsToggle = document.getElementById('email-alerts-toggle-page');
const weeklyReportToggle = document.getElementById('weekly-report-toggle-page');

// Advanced Settings
const blockPopUpsToggle = document.getElementById('block-pop-ups-toggle');
const safeSearchToggle = document.getElementById('safe-search-toggle');

// Save All Settings Button
const settingsSaveAllBtn = document.getElementById('settings-save-all-btn');

// Prevent double-binding of listeners when init runs more than once
let SETTINGS_LISTENERS_BOUND = false;

// Storage Keys
const SETTINGS_STORAGE_KEY = 'phishnetSettings';
const USER_PROFILE_STORAGE_KEY = 'phishnetUserProfile';
const PROFILE_PICTURE_STORAGE_KEY = 'phishnetProfilePicture';
const CROP_STAGE_SIZE = 280;
const CROP_EXPORT_SIZE = 240;

const cropState = {
    imageData: null,
    imgNaturalWidth: 0,
    imgNaturalHeight: 0,
    scale: 1,
    minScale: 1,
    offsetX: 0,
    offsetY: 0,
    dragging: false,
    dragStartX: 0,
    dragStartY: 0
};

// Build a full name string from available fields
function getFullName(user) {
    if (!user) return '';
    if (user.firstName || user.lastName) {
        return `${user.firstName || ''} ${user.lastName || ''}`.trim();
    }
    return user.name || '';
}

// Split a full name into first/last for backend compatibility
function splitName(fullName) {
    const parts = (fullName || '').trim().split(/\s+/);
    const firstName = parts.shift() || '';
    const lastName = parts.join(' ') || '';
    return { firstName, lastName };
}

// Cropper Helpers
function updateCropperTransform() {
    if (!cropperImage) return;
    cropperImage.style.transform = `translate(-50%, -50%) translate(${cropState.offsetX}px, ${cropState.offsetY}px) scale(${cropState.scale})`;
}

function openCropper(imageData) {
    if (!cropperModal || !cropperImage) return;
    cropState.imageData = imageData;
    cropperImage.src = imageData;
    cropperModal.classList.add('open');

    cropperImage.onload = () => {
        cropState.imgNaturalWidth = cropperImage.naturalWidth;
        cropState.imgNaturalHeight = cropperImage.naturalHeight;
        const circleDiameter = CROP_EXPORT_SIZE;
        const minScaleX = circleDiameter / cropState.imgNaturalWidth;
        const minScaleY = circleDiameter / cropState.imgNaturalHeight;
        cropState.minScale = Math.max(minScaleX, minScaleY);
        // Default slightly zoomed-out feel (use minimum coverage scale)
        cropState.scale = cropState.minScale;
        cropState.offsetX = 0;
        cropState.offsetY = 0;
        if (cropperZoom) {
            cropperZoom.min = cropState.minScale.toFixed(2);
            cropperZoom.max = Math.max(3, (cropState.minScale * 3)).toFixed(2);
            cropperZoom.value = cropState.scale.toFixed(2);
        }
        updateCropperTransform();
    };
}

function closeCropper() {
    if (!cropperModal) return;
    cropperModal.classList.remove('open');
    cropState.dragging = false;
}

function getCroppedDataUrl() {
    if (!cropperImage) return null;
    const canvas = document.createElement('canvas');
    canvas.width = CROP_EXPORT_SIZE;
    canvas.height = CROP_EXPORT_SIZE;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    ctx.save();
    ctx.beginPath();
    ctx.arc(CROP_EXPORT_SIZE / 2, CROP_EXPORT_SIZE / 2, CROP_EXPORT_SIZE / 2, 0, Math.PI * 2);
    ctx.clip();

    const drawWidth = cropState.imgNaturalWidth * cropState.scale;
    const drawHeight = cropState.imgNaturalHeight * cropState.scale;
    const drawX = (CROP_EXPORT_SIZE / 2) + cropState.offsetX - (drawWidth / 2);
    const drawY = (CROP_EXPORT_SIZE / 2) + cropState.offsetY - (drawHeight / 2);

    ctx.drawImage(cropperImage, drawX, drawY, drawWidth, drawHeight);
    ctx.restore();
    return canvas.toDataURL('image/png');
}

// Initialize Settings Page
async function initializeSettingsPage() {
    console.log('🔧 Initializing Settings Page...');
    
    // Load user profile data
    await loadUserProfile();
    
    // Load saved settings
    await loadSettings();
    
    // Setup event listeners
    setupSettingsEventListeners();
    
    console.log('✓ Settings Page Initialized');
}

// Load User Profile
async function loadUserProfile() {
    let userData = null;
    console.log('📋 Loading user profile...');

    // Only attempt API call if the API wrapper is available and settings API usage is enabled
    if (typeof PhishNetAPI !== 'undefined' && USE_SETTINGS_API) {
        try {
            const profile = await PhishNetAPI.getUserProfile();
            if (profile && profile.data) {
                userData = profile.data;
                console.log('✓ User profile loaded from API');
            }
        } catch (error) {
            console.warn('⚠ Could not load profile from API, trying local storage:', error);
        }
    } else {
        console.log('ℹ Skipping API profile load (API unavailable or disabled), using local storage/popup state');
    }

    if (!userData) {
        const stored = await new Promise((resolve) => {
            chrome.storage.local.get([USER_PROFILE_STORAGE_KEY], (result) => {
                resolve(result[USER_PROFILE_STORAGE_KEY]);
            });
        });
        if (stored) {
            userData = stored;
            console.log('✓ User profile loaded from local storage');
        }
    }

    if (!userData && window.__phishnetState?.currentUser) {
        userData = window.__phishnetState.currentUser;
        console.log('✓ User profile loaded from popup state');
    }

    if (userData) {
        const fullName = getFullName(userData);
        if (fullName) profileNameInput.value = fullName;
        if (userData.email) {
            profileEmailInput.value = userData.email;
            profileEmailInput.readOnly = true;
        }

        // Store profile locally for future loads
        await chrome.storage.local.set({
            [USER_PROFILE_STORAGE_KEY]: {
                name: fullName,
                email: userData.email || ''
            }
        });
    } else {
        console.log('⚠ No user profile found');
    }
    
    // Load profile picture from storage
    const stored = await new Promise((resolve) => {
        chrome.storage.local.get([PROFILE_PICTURE_STORAGE_KEY], (result) => {
            resolve(result[PROFILE_PICTURE_STORAGE_KEY]);
        });
    });
    
    if (stored) {
        const img = document.createElement('img');
        img.src = stored;
        profilePicture.innerHTML = '';
        profilePicture.appendChild(img);
        console.log('✓ Profile picture loaded');
        // Sync to popup state and header avatar
        if (window.__phishnetState) {
            window.__phishnetState.currentUser = {
                ...(window.__phishnetState.currentUser || {}),
                profilePicture: stored
            };
            if (typeof window.saveState === 'function') {
                window.saveState();
            }
            if (typeof window.refreshHeaderAvatar === 'function') {
                window.refreshHeaderAvatar();
            }
        }
    }
}

// Load Settings from Storage
async function loadSettings() {
    console.log('⚙️ Loading settings from storage...');
    let stored = {};

    // Try backend first (only if flag enabled)
    if (USE_SETTINGS_API) {
        try {
            const response = await PhishNetAPI.getUserSettings();
            if (response?.data) {
                stored = response.data.settings || {};
                const backendPicture = response.data.profilePicture;
                if (backendPicture) {
                    await chrome.storage.local.set({ [PROFILE_PICTURE_STORAGE_KEY]: backendPicture });
                    if (window.__phishnetState) {
                        window.__phishnetState.currentUser = {
                            ...(window.__phishnetState.currentUser || {}),
                            profilePicture: backendPicture
                        };
                        if (typeof window.saveState === 'function') window.saveState();
                        if (typeof window.refreshHeaderAvatar === 'function') window.refreshHeaderAvatar();
                    }
                    // Reflect in UI immediately
                    const img = document.createElement('img');
                    img.src = backendPicture;
                    profilePicture.innerHTML = '';
                    profilePicture.appendChild(img);
                }
            }
        } catch (error) {
            console.warn('⚠ Could not load settings from backend, will use local storage:', error);
        }
    }

    // Fallback/local merge
    const storedLocal = await new Promise((resolve) => {
        chrome.storage.local.get([SETTINGS_STORAGE_KEY], (result) => {
            resolve(result[SETTINGS_STORAGE_KEY] || {});
        });
    });
    stored = { ...storedLocal, ...stored }; // backend wins on overlap
    
    // Apply saved settings to toggles with defaults
    scanUrlsToggle.checked = stored.scanUrls !== undefined ? stored.scanUrls : true;
    scanEmailsToggle.checked = stored.scanEmails !== undefined ? stored.scanEmails : true;
    realTimeProtectionToggle.checked = stored.realTimeProtection !== undefined ? stored.realTimeProtection : false;
    
    dataSharingToggle.checked = stored.dataSharing !== undefined ? stored.dataSharing : false;
    autoSubmitToggle.checked = stored.autoSubmit !== undefined ? stored.autoSubmit : false;
    
    notifyToggle.checked = stored.notifications !== undefined ? stored.notifications : true;
    emailAlertsToggle.checked = stored.emailAlerts !== undefined ? stored.emailAlerts : false;
    weeklyReportToggle.checked = stored.weeklyReport !== undefined ? stored.weeklyReport : false;
    
    blockPopUpsToggle.checked = stored.blockPopUps !== undefined ? stored.blockPopUps : false;
    safeSearchToggle.checked = stored.safeSearch !== undefined ? stored.safeSearch : true;
    
    console.log('✓ Settings loaded:', stored);
}

// Setup Event Listeners
function setupSettingsEventListeners() {
    if (SETTINGS_LISTENERS_BOUND) return;
    SETTINGS_LISTENERS_BOUND = true;

    // Back button
    if (settingsBackBtn) {
        settingsBackBtn.addEventListener('click', () => {
            if (typeof window.showPage === 'function' && dashboardPage) {
                window.showPage(dashboardPage);
            } else {
                console.warn('⚠ Unable to navigate back: showPage or dashboardPage missing');
            }
        });
    } else {
        console.warn('⚠ settingsBackBtn not found');
    }
    
    // Profile picture upload
    if (profilePictureBtn) {
        profilePictureBtn.addEventListener('click', () => {
            profilePictureInput.click();
        });
    }
    
    if (profilePictureInput) {
        profilePictureInput.addEventListener('change', (e) => {
            handleProfilePictureUpload(e);
        });
    }

    if (cropperCancelBtn) {
        cropperCancelBtn.addEventListener('click', () => {
            closeCropper();
            if (profilePictureInput) profilePictureInput.value = '';
        });
    }

    if (cropperApplyBtn) {
        cropperApplyBtn.addEventListener('click', () => {
            applyCroppedPhoto();
        });
    }

    if (cropperZoom) {
        cropperZoom.addEventListener('input', () => {
            const nextScale = Math.max(cropState.minScale, parseFloat(cropperZoom.value || '1'));
            cropState.scale = nextScale;
            updateCropperTransform();
        });
    }

    if (cropperStage) {
        cropperStage.addEventListener('pointerdown', (e) => {
            handleCropperPointerDown(e);
            cropperStage.setPointerCapture(e.pointerId);
        });
        cropperStage.addEventListener('pointermove', (e) => {
            handleCropperPointerMove(e);
        });
        cropperStage.addEventListener('pointerup', (e) => {
            handleCropperPointerUp();
            cropperStage.releasePointerCapture(e.pointerId);
        });
        cropperStage.addEventListener('pointercancel', () => {
            handleCropperPointerUp();
        });
        cropperStage.addEventListener('wheel', (e) => {
            e.preventDefault();
            const delta = -e.deltaY;
            const step = delta > 0 ? 0.05 : -0.05;
            const maxScale = Math.max(3, cropState.minScale * 3);
            const nextScale = Math.min(maxScale, Math.max(cropState.minScale, cropState.scale + step));
            cropState.scale = nextScale;
            if (cropperZoom) {
                cropperZoom.value = cropState.scale.toFixed(2);
            }
            updateCropperTransform();
        }, { passive: false });
    }
    
    // Profile save button
    if (profileSaveBtn) {
        profileSaveBtn.addEventListener('click', () => {
            saveProfileChanges();
        });
    }
    
    // Settings save all button
    if (settingsSaveAllBtn) {
        settingsSaveAllBtn.addEventListener('click', () => {
            saveAllSettings();
        });
    }
}

// Handle Profile Picture Upload
function handleProfilePictureUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Check file size (max 1MB)
    if (file.size > 1024 * 1024) {
        showToast('Profile picture must be less than 1MB');
        return;
    }
    
    // Check file type
    if (!file.type.startsWith('image/')) {
        showToast('Please select a valid image file');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = (e) => {
        const imageData = e.target.result;
        openCropper(imageData);
        console.log('✓ Profile picture selected, opening cropper');
    };
    reader.readAsDataURL(file);
}

async function applyCroppedPhoto() {
    const finalImage = getCroppedDataUrl();
    if (!finalImage) {
        showToast('Could not process image');
        return;
    }

    const img = document.createElement('img');
    img.src = finalImage;
    profilePicture.innerHTML = '';
    profilePicture.appendChild(img);

    await chrome.storage.local.set({
        [PROFILE_PICTURE_STORAGE_KEY]: finalImage
    });

    if (window.__phishnetState) {
        window.__phishnetState.currentUser = {
            ...(window.__phishnetState.currentUser || {}),
            profilePicture: finalImage
        };
        if (typeof window.saveState === 'function') {
            window.saveState();
        }
        if (typeof window.refreshHeaderAvatar === 'function') {
            window.refreshHeaderAvatar();
        }
    }

    closeCropper();
    if (profilePictureInput) profilePictureInput.value = '';
    showToast('Profile photo updated');
    console.log('✓ Profile photo cropped and saved');
}

function handleCropperPointerDown(e) {
    if (!cropState) return;
    cropState.dragging = true;
    cropState.dragStartX = e.clientX;
    cropState.dragStartY = e.clientY;
}

function handleCropperPointerMove(e) {
    if (!cropState.dragging) return;
    const dx = e.clientX - cropState.dragStartX;
    const dy = e.clientY - cropState.dragStartY;
    cropState.offsetX += dx;
    cropState.offsetY += dy;
    cropState.dragStartX = e.clientX;
    cropState.dragStartY = e.clientY;
    updateCropperTransform();
}

function handleCropperPointerUp() {
    cropState.dragging = false;
}

// Save Profile Changes
async function saveProfileChanges() {
    try {
        const name = profileNameInput.value.trim();
        
        if (!name) {
            showToast('Please enter your name');
            return;
        }

        // Basic length guardrail (UI level)
        if (name.length < 2) {
            showToast('Name must be at least 2 characters');
            return;
        }

        // Enforce schema requirements (min length 2 for first/last)
        const existing = window.__phishnetState?.currentUser || {};
        let { firstName, lastName } = splitName(name);
        if (!firstName || firstName.length < 2) firstName = existing.firstName || 'User';
        if (!lastName || lastName.length < 2) lastName = existing.lastName || 'User';
        
        // Show saving state
        profileSaveBtn.disabled = true;
        profileSaveBtn.textContent = 'Saving...';
        
        // Prepare update data for backend
        const updateData = {
            firstName,
            lastName
        };
        
        // Try to update via API
        try {
            const response = await PhishNetAPI.request('/users/profile', {
                method: 'PUT',
                body: JSON.stringify(updateData)
            });
            
            console.log('✓ Profile updated on server:', response);
            // Prefer server-returned names if available
            if (response?.data) {
                const updated = response.data;
                firstName = updated.firstName || firstName;
                lastName = updated.lastName || lastName;
            }
        } catch (error) {
            console.warn('⚠ Could not update profile on server:', error);
            // Continue - we'll still save locally
        }
        
        // Store profile locally
        const fullName = `${firstName} ${lastName}`.trim();
        const profile = {
            name: fullName,
            email: profileEmailInput.value,
            firstName,
            lastName
        };
        
        await chrome.storage.local.set({
            [USER_PROFILE_STORAGE_KEY]: profile
        });

        // Sync to popup state and persist UI state
        if (window.__phishnetState) {
            window.__phishnetState.currentUser = {
                ...(window.__phishnetState.currentUser || {}),
                name: fullName,
                email: profileEmailInput.value,
                firstName,
                lastName
            };
            if (typeof window.saveState === 'function') {
                window.saveState();
            }
            if (typeof window.refreshHeaderAvatar === 'function') {
                window.refreshHeaderAvatar();
            }
        }
        
        showToast('Changes saved successfully');
        console.log('✓ Profile changes saved');

        // Persist profile picture to backend as a reliability fallback (only if enabled)
        if (USE_SETTINGS_API) {
            try {
                const storedPicture = await new Promise((resolve) => {
                    chrome.storage.local.get([PROFILE_PICTURE_STORAGE_KEY], (result) => {
                        resolve(result[PROFILE_PICTURE_STORAGE_KEY]);
                    });
                });

                await PhishNetAPI.request('/users/settings', {
                    method: 'POST',
                    body: JSON.stringify({ profilePicture: storedPicture })
                });
                console.log('✓ Profile picture synced with backend');
            } catch (syncError) {
                console.warn('⚠ Could not sync profile picture with backend:', syncError);
            }
        }
        
    } catch (error) {
        console.error('❌ Error saving profile:', error);
        const message = error?.message || 'Error saving profile. Please try again.';
        showToast(message);
    } finally {
        profileSaveBtn.disabled = false;
        profileSaveBtn.textContent = 'Save Profile Changes';
    }
}

// Save All Settings
async function saveAllSettings() {
    try {
        // Show saving state
        settingsSaveAllBtn.disabled = true;
        settingsSaveAllBtn.textContent = 'Saving...';
        
        // Collect all settings
        const settings = {
            // Scanning
            scanUrls: scanUrlsToggle.checked,
            scanEmails: scanEmailsToggle.checked,
            realTimeProtection: realTimeProtectionToggle.checked,
            
            // Privacy
            dataSharing: dataSharingToggle.checked,
            autoSubmit: autoSubmitToggle.checked,
            
            // Notifications
            notifications: notifyToggle.checked,
            emailAlerts: emailAlertsToggle.checked,
            weeklyReport: weeklyReportToggle.checked,
            
            // Advanced
            blockPopUps: blockPopUpsToggle.checked,
            safeSearch: safeSearchToggle.checked,
            
            // Metadata
            lastUpdated: new Date().toISOString()
        };
        
        // Save to local storage
        await chrome.storage.local.set({
            [SETTINGS_STORAGE_KEY]: settings
        });
        
        // Try to sync with backend (only if enabled)
        if (USE_SETTINGS_API) {
            try {
                const storedPicture = await new Promise((resolve) => {
                    chrome.storage.local.get([PROFILE_PICTURE_STORAGE_KEY], (result) => {
                        resolve(result[PROFILE_PICTURE_STORAGE_KEY]);
                    });
                });

                const response = await PhishNetAPI.request('/users/settings', {
                    method: 'POST',
                    body: JSON.stringify({ settings, profilePicture: storedPicture })
                });
                console.log('✓ Settings synced with backend:', response);
            } catch (error) {
                console.warn('⚠ Could not sync settings with backend:', error);
                // Settings are still saved locally, that's okay
            }
        }
        
        showToast('All settings saved successfully! ✓');
        console.log('✓ All settings saved:', settings);
        
    } catch (error) {
        console.error('❌ Error saving settings:', error);
        showToast('Error saving settings. Please try again.');
    } finally {
        settingsSaveAllBtn.disabled = false;
        settingsSaveAllBtn.textContent = 'Save All Settings';
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Check if API is available (it should be from popup.js)
    if (typeof PhishNetAPI !== 'undefined' && typeof showPage !== 'undefined' && typeof showToast !== 'undefined') {
        initializeSettingsPage();
    } else {
        console.warn('⚠ Required dependencies not available yet');
        // Try again after a short delay
        setTimeout(initializeSettingsPage, 500);
    }
});

// Export initialization function for use by popup.js (and ensure a stable reference)
window.initializeSettingsPage = initializeSettingsPage;
window.settingsPageInit = window.settingsPageInit || initializeSettingsPage;

})();
