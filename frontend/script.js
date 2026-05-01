document.documentElement.classList.add("js");

try {
  const hasInitialSession =
    Boolean(localStorage.getItem("authToken")) ||
    Boolean(localStorage.getItem("adminToken"));
  document.documentElement.classList.toggle(
    "has-auth-session",
    hasInitialSession,
  );
} catch (error) {
  document.documentElement.classList.remove("has-auth-session");
}

const App = (() => {
  const WHATSAPP_PHONE = "2349072560420";
  const CONTACT_EMAIL = "Wisdomadiele57@gmail.com";
  const DEFAULT_MAP_QUERY = "Seventh-day Adventist church near me";
  const MEMBER_DISPLAY_NAME_KEY = "memberDisplayName";

  const getConfigString = (key) => {
    const value = window.APP_CONFIG?.[key] ?? window.__APP_CONFIG__?.[key];
    return typeof value === "string" ? value.trim() : "";
  };

  const GOOGLE_ANALYTICS_ID = getConfigString("GOOGLE_ANALYTICS_ID");
  const GOOGLE_MAPS_EMBED_URL = getConfigString("GOOGLE_MAPS_EMBED_URL");
  const GOOGLE_MAPS_DIRECTIONS_URL = getConfigString(
    "GOOGLE_MAPS_DIRECTIONS_URL",
  );

  const isLocalHost = (() => {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0") {
      return true;
    }
    if (/^10\./.test(host) || /^192\.168\./.test(host)) {
      return true;
    }
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) {
      return true;
    }
    return false;
  })();

  const normalizeApiBase = (value) => {
    if (!value) return value;
    const trimmed = value.replace(/\/+$/, "");
    return /\/api$/i.test(trimmed) ? trimmed : `${trimmed}/api`;
  };

  const getConfiguredApiBase = () => {
    const windowValue =
      window.APP_CONFIG?.API_BASE || window.__APP_CONFIG__?.API_BASE;
    if (typeof windowValue === "string" && windowValue.trim()) {
      return normalizeApiBase(windowValue.trim());
    }

    const metaValue = document
      .querySelector('meta[name="api-base-url"]')
      ?.getAttribute("content");
    if (typeof metaValue === "string" && metaValue.trim()) {
      return normalizeApiBase(metaValue.trim());
    }

    return null;
  };

  const configuredApiBase = getConfiguredApiBase();
  const API_BASE = normalizeApiBase(
    configuredApiBase || window.location.origin,
  );
  const BACKEND_ORIGIN = API_BASE.replace(/\/api\/?$/, "");
  const POST_AUTH_REDIRECT_KEY = "postAuthRedirect";
  const ADMIN_DASHBOARD_PATH = "admin-dashboard.html";
  const DAILY_PROMISE_COLLAPSE_MIN_CHARS = 260;
  const RESOURCE_PAGE_SIZE = 6;
  const RESOURCE_MAX_LIMIT = 100;
  const ALL_MATERIALS_PAGE_SIZE = 24;
  const COMMUNITY_PAGE = "community.html";
  const COMMUNITY_READING_THREAD_ID = 1;
  const SUPPORT_PAYMENT_PAGE = "support-payment.html";
  const MINISTRY_TIME_ZONE = "Africa/Lagos";
  const currentPathName = window.location.pathname.toLowerCase();
  const onSupportPaymentPage =
    currentPathName.endsWith(`/${SUPPORT_PAYMENT_PAGE}`) ||
    currentPathName.endsWith(SUPPORT_PAYMENT_PAGE);

  const state = {
    token:
      localStorage.getItem("authToken") || localStorage.getItem("adminToken"),
    user: null,
    authMode: "login",
  };

  const resourceState = {
    items: [],
    fromApi: false,
    displayed: 0,
    total: 0,
  };

  const allMaterialsState = {
    page: 1,
    limit: ALL_MATERIALS_PAGE_SIZE,
    total: 0,
    pages: 1,
    search: "",
    category: "",
    type: "",
    loading: false,
  };

  const supportState = {
    config: {
      heading: "Support the Ministry",
      intro:
        "Your support helps sustain biblical teaching, prayer care, counseling, outreach, and ministry media.",
      currency: "NGN",
      bank_name: "",
      account_name: "",
      account_number: "",
      payment_note:
        "After sending your support, reach the ministry through WhatsApp or email with your transfer details so it can be confirmed quickly.",
      payment_link: "",
      support_email: "admin@spiritualcenter.com",
      support_whatsapp: "2349072560420",
    },
  };

  const communityState = {
    threads: [],
    activeFilter: "all",
    focusType: "",
    focusId: "",
  };

  const fallbackResources = [
    {
      title: "Foundations of Christian Faith",
      description:
        "A structured guide for growing confidence in Christ and in the authority of scripture.",
      category: "teaching",
      type: "guide",
      link: "#contact",
    },
    {
      title: "Strategic Patterns of Prayer",
      description:
        "A practical prayer framework for families, leaders, and ministry teams.",
      category: "prayer",
      type: "study",
      link: "#contact",
    },
    {
      title: "Leadership with Integrity",
      description:
        "Biblical leadership principles for influence, discipline, stewardship, and service.",
      category: "leadership",
      type: "teaching",
      link: "#contact",
    },
  ];

  const DAILY_BIBLE_READING_DAY_MS = 24 * 60 * 60 * 1000;
  const DAILY_BIBLE_READING_ANCHOR = Object.freeze({
    date: "2026-03-12",
    reference: "2 Kings 17",
    version: "NKJV",
  });
  const DAILY_BIBLE_BOOKS = Object.freeze([
    ["Genesis", 50],
    ["Exodus", 40],
    ["Leviticus", 27],
    ["Numbers", 36],
    ["Deuteronomy", 34],
    ["Joshua", 24],
    ["Judges", 21],
    ["Ruth", 4],
    ["1 Samuel", 31],
    ["2 Samuel", 24],
    ["1 Kings", 22],
    ["2 Kings", 25],
    ["1 Chronicles", 29],
    ["2 Chronicles", 36],
    ["Ezra", 10],
    ["Nehemiah", 13],
    ["Esther", 10],
    ["Job", 42],
    ["Psalms", 150],
    ["Proverbs", 31],
    ["Ecclesiastes", 12],
    ["Song of Solomon", 8],
    ["Isaiah", 66],
    ["Jeremiah", 52],
    ["Lamentations", 5],
    ["Ezekiel", 48],
    ["Daniel", 12],
    ["Hosea", 14],
    ["Joel", 3],
    ["Amos", 9],
    ["Obadiah", 1],
    ["Jonah", 4],
    ["Micah", 7],
    ["Nahum", 3],
    ["Habakkuk", 3],
    ["Zephaniah", 3],
    ["Haggai", 2],
    ["Zechariah", 14],
    ["Malachi", 4],
    ["Matthew", 28],
    ["Mark", 16],
    ["Luke", 24],
    ["John", 21],
    ["Acts", 28],
    ["Romans", 16],
    ["1 Corinthians", 16],
    ["2 Corinthians", 13],
    ["Galatians", 6],
    ["Ephesians", 6],
    ["Philippians", 4],
    ["Colossians", 4],
    ["1 Thessalonians", 5],
    ["2 Thessalonians", 3],
    ["1 Timothy", 6],
    ["2 Timothy", 4],
    ["Titus", 3],
    ["Philemon", 1],
    ["Hebrews", 13],
    ["James", 5],
    ["1 Peter", 5],
    ["2 Peter", 3],
    ["1 John", 5],
    ["2 John", 1],
    ["3 John", 1],
    ["Jude", 1],
    ["Revelation", 22],
  ]);
  const DAILY_BIBLE_CHAPTERS = DAILY_BIBLE_BOOKS.reduce(
    (chapters, [book, count]) => {
      for (let chapter = 1; chapter <= count; chapter += 1) {
        chapters.push({
          book,
          chapter,
          reference: `${book} ${chapter}`,
        });
      }

      return chapters;
    },
    [],
  );
  const DAILY_BIBLE_CHAPTER_INDEX = new Map(
    DAILY_BIBLE_CHAPTERS.map((entry, index) => [
      entry.reference.toLowerCase(),
      index,
    ]),
  );

  const ui = {
    header: document.getElementById("siteHeader"),
    navToggle: document.getElementById("navToggle"),
    mainNav: document.getElementById("mainNav"),
    navOverlay: document.getElementById("navOverlay"),
    navDropdownTrigger: document.getElementById("exploreDropdownBtn"),
    navDropdownMenu: document.getElementById("exploreDropdownMenu"),
    adminEntryButtons: Array.from(
      document.querySelectorAll(
        '.header-actions a[href="admin-login.html"], .mobile-nav-actions a[href="admin-login.html"]',
      ),
    ).map((button) => {
      if (!button.dataset.adminDefaultHtml) {
        button.dataset.adminDefaultHtml = button.innerHTML;
      }
      if (!button.dataset.adminDefaultLabel) {
        button.dataset.adminDefaultLabel = button.textContent.trim();
      }
      if (!button.dataset.adminDefaultHref) {
        button.dataset.adminDefaultHref =
          button.getAttribute("href") || "admin-login.html";
      }
      return button;
    }),
    openAuthBtns: Array.from(document.querySelectorAll("[data-open-auth]")).map(
      (button) => {
        if (!button.dataset.authDefaultHtml) {
          button.dataset.authDefaultHtml = button.innerHTML;
        }
        if (!button.dataset.authDefaultLabel) {
          button.dataset.authDefaultLabel = button.textContent.trim();
        }
        return button;
      },
    ),
    resourceLoginBtn: document.getElementById("resourceLoginBtn"),
    logoutBtn: document.getElementById("logoutBtn"),
    userBadge: document.getElementById("userBadge"),
    userName: document.getElementById("userName"),
    userRole: document.getElementById("userRole"),
    userAvatar: document.getElementById("userAvatar"),
    resourceGrid: document.getElementById("resourceGrid"),
    resourceNotice: document.getElementById("resourceNotice"),
    resourceLoadMore: document.getElementById("resourceLoadMore"),
    resourceViewAll: document.getElementById("resourceViewAll"),
    resourceCount: document.getElementById("resourceCount"),
    allMaterialsGrid: document.getElementById("allMaterialsGrid"),
    allMaterialsNotice: document.getElementById("allMaterialsNotice"),
    allMaterialsForm: document.getElementById("allMaterialsFilters"),
    allMaterialsSearch: document.getElementById("allMaterialsSearch"),
    allMaterialsCategory: document.getElementById("allMaterialsCategory"),
    allMaterialsType: document.getElementById("allMaterialsType"),
    allMaterialsClear: document.getElementById("allMaterialsClear"),
    allMaterialsPrev: document.getElementById("allMaterialsPrev"),
    allMaterialsNext: document.getElementById("allMaterialsNext"),
    allMaterialsPage: document.getElementById("allMaterialsPage"),
    authModal: document.getElementById("authModal"),
    authModalTitle: document.getElementById("authModalTitle"),
    authModalSubtitle: document.getElementById("authModalSubtitle"),
    authTabs: Array.from(document.querySelectorAll(".auth-tab")),
    authModeButtons: Array.from(document.querySelectorAll("[data-auth-mode]")),
    authViews: Array.from(document.querySelectorAll(".auth-view")),
    closeAuthBtn: document.getElementById("closeAuthBtn"),
    loginForm: document.getElementById("loginForm"),
    loginEmail: document.getElementById("loginEmail"),
    loginPassword: document.getElementById("loginPassword"),
    loginSubmitBtn: document.getElementById("loginSubmitBtn"),
    registerForm: document.getElementById("registerForm"),
    registerUsername: document.getElementById("registerUsername"),
    registerEmail: document.getElementById("registerEmail"),
    registerPassword: document.getElementById("registerPassword"),
    registerConfirmPassword: document.getElementById("registerConfirmPassword"),
    registerSubmitBtn: document.getElementById("registerSubmitBtn"),
    recoverForm: document.getElementById("recoverForm"),
    recoverEmail: document.getElementById("recoverEmail"),
    recoverCode: document.getElementById("recoverCode"),
    recoverPassword: document.getElementById("recoverPassword"),
    recoverConfirmPassword: document.getElementById("recoverConfirmPassword"),
    requestRecoveryBtn: document.getElementById("requestRecoveryBtn"),
    recoverSubmitBtn: document.getElementById("recoverSubmitBtn"),
    authMessage: document.getElementById("authMessage"),
    protectedSectionLinks: Array.from(
      document.querySelectorAll("[data-protected-section]"),
    ),
    contactForm: document.getElementById("contactForm"),
    contactName: document.getElementById("contactName"),
    contactEmail: document.getElementById("contactEmail"),
    contactSubject: document.getElementById("contactSubject"),
    contactMessage: document.getElementById("contactMessage"),
    supportHeading: document.getElementById("supportHeading"),
    supportIntro: document.getElementById("supportIntro"),
    supportCurrencyBadge: document.getElementById("supportCurrencyBadge"),
    supportBankName: document.getElementById("supportBankName"),
    supportAccountName: document.getElementById("supportAccountName"),
    supportAccountNumber: document.getElementById("supportAccountNumber"),
    supportPaymentNote: document.getElementById("supportPaymentNote"),
    supportEmailLink: document.getElementById("supportEmailLink"),
    supportWhatsappLink: document.getElementById("supportWhatsappLink"),
    supportPaymentLink: document.getElementById("supportPaymentLink"),
    googleMapEmbed: document.getElementById("googleMapEmbed"),
    googleDirectionsLink: document.getElementById("googleDirectionsLink"),
    year: document.getElementById("year"),
    // Prayer Page
    prayerPageForm: document.getElementById("prayerForm"),
    prayerPageName: document.getElementById("prayerName"),
    prayerPageEmail: document.getElementById("prayerEmail"),
    prayerPageWhatsapp: document.getElementById("prayerWhatsapp"),
    prayerPageRequest: document.getElementById("prayerRequest"),
    prayerPageAnonymous: document.getElementById("prayerAnonymous"),
    prayerFormContainer: document.getElementById("prayer-form-container"),
    prayerBookingForm: document.getElementById("prayerBookingForm"),
    prayerBookingName: document.getElementById("prayerBookingName"),
    prayerBookingEmail: document.getElementById("prayerBookingEmail"),
    prayerBookingWhatsapp: document.getElementById("prayerBookingWhatsapp"),
    prayerBookingAvailability: document.getElementById(
      "prayerBookingAvailability",
    ),
    prayerBookingFocus: document.getElementById("prayerBookingFocus"),
    // Counseling Page
    counselingPageForm: document.getElementById("counselingForm"),
    counselingIntent: document.getElementById("counselingIntent"),
    counselingType: document.getElementById("counselingType"),
    counselingWhatsapp: document.getElementById("counselingWhatsapp"),
    counselingDescription: document.getElementById("counselingDescription"),
    counselingAvailability: document.getElementById("counselingAvailability"),
    counselingFormContainer: document.getElementById(
      "counseling-form-container",
    ),
    // General
    loginWall: document.getElementById("login-wall"),
    loginBtn: document.getElementById("login-btn"),
    formMessage: document.getElementById("form-message"),
    // Daily Promise
    dailyUpdatePromiseText: document.getElementById("dailyUpdatePromiseText"),
    dailyUpdateToggleBtn: document.getElementById("dailyUpdateToggleBtn"),
    dailyUpdatePromiseAuthor: document.getElementById(
      "dailyUpdatePromiseAuthor",
    ),
    dailyUpdatePromiseDate: document.getElementById("dailyUpdatePromiseDate"),
    dailyPromiseHistory: document.getElementById("dailyPromiseHistory"),
    dailyPromiseHistoryList: document.getElementById("dailyPromiseHistoryList"),
    dailyPromiseCommentsList: document.getElementById(
      "dailyPromiseCommentsList",
    ),
    dailyPromiseCommentForm: document.getElementById("dailyPromiseCommentForm"),
    dailyPromiseCommentInput: document.getElementById(
      "dailyPromiseCommentInput",
    ),
    dailyPromiseCommunityLink: document.getElementById(
      "dailyPromiseCommunityLink",
    ),
    devotionList: document.getElementById("devotionList"),
    devotionNotice: document.getElementById("devotionNotice"),
    communityNotice: document.getElementById("communityNotice"),
    communityThreads: document.getElementById("communityThreads"),
    communityFilterButtons: Array.from(
      document.querySelectorAll("[data-community-filter]"),
    ),
  };

  function init() {
    setupGoogleAnalytics();
    setupGoogleMap();
    setYear();
    setupDailyBibleReading();
    setupScrollHeader();
    setupMobileNav();
    setupNavDropdown();
    setupActiveNavTracking();
    setupRevealAnimations();
    setupModal();
    setupResourceControls();
    setupAllMaterialsPage();
    setupProtectedSectionLinks();
    handleAuthEntryIntent();
    setupContactForm();
    setupLoginForm();
    setupRegisterForm();
    setupRecoverForm();
    setupPrayerPage();
    setupCounselingPage();
    setupDailyPromise();
    setupDevotionPage();
    setupCommunityPage();
    loadSupportConfig();

    updateAuthUI();
    hydrateSession().finally(() => {
      loadResources();
      loadAllMaterials();
    });
  }

  function setYear() {
    if (ui.year) {
      ui.year.textContent = String(new Date().getFullYear());
    }
  }

  function getStoredMemberDisplayName() {
    try {
      return String(localStorage.getItem(MEMBER_DISPLAY_NAME_KEY) || "").trim();
    } catch (error) {
      return "";
    }
  }

  function persistMemberDisplayName(user = null, fallback = "") {
    const displayName = String(
      user?.username || user?.email || fallback || "",
    ).trim();

    if (!displayName) {
      return "";
    }

    try {
      localStorage.setItem(MEMBER_DISPLAY_NAME_KEY, displayName);
    } catch (error) {
      return displayName;
    }

    return displayName;
  }

  function isPrivilegedUser(user = null) {
    const normalizedEmail = String(user?.email || "")
      .trim()
      .toLowerCase();

    return Boolean(
      user &&
      (user.role === "admin" ||
        user.role === "super_admin" ||
        normalizedEmail === "admin@spiritualcenter.com"),
    );
  }

  function getStoredAdminDisplayName() {
    try {
      return String(
        localStorage.getItem("adminUsername") ||
          localStorage.getItem("adminEmail") ||
          "",
      ).trim();
    } catch (error) {
      return "";
    }
  }

  function formatAdminFirstName(value = "") {
    const normalized = String(value || "").trim();
    if (!normalized) return "";

    const source = normalized.includes("@")
      ? normalized.split("@")[0]
      : normalized;
    const firstSegment =
      source
        .split(/[\s._-]+/)
        .map((part) => part.trim())
        .find(Boolean) || source;

    if (!firstSegment) return "";

    return firstSegment.charAt(0).toUpperCase() + firstSegment.slice(1);
  }

  function getAdminSessionSummary() {
    const currentAdminUser = isPrivilegedUser(state.user) ? state.user : null;
    const hasAdminSession = Boolean(
      localStorage.getItem("adminToken") || currentAdminUser,
    );
    const displayName =
      currentAdminUser?.username ||
      currentAdminUser?.email ||
      getStoredAdminDisplayName();
    const firstName = formatAdminFirstName(displayName) || "Admin";

    return {
      hasAdminSession,
      displayName,
      firstName,
    };
  }

  function renderAdminEntryButton(
    button,
    { hasAdminSession, displayName, firstName },
  ) {
    if (!button) return;

    if (hasAdminSession) {
      button.textContent = firstName;
      button.setAttribute("href", ADMIN_DASHBOARD_PATH);
      button.dataset.adminState = "signed-in";
      button.setAttribute(
        "aria-label",
        displayName
          ? `Open admin dashboard for ${displayName}`
          : "Open admin dashboard",
      );
      button.title = displayName || firstName;
      return;
    }

    button.innerHTML =
      button.dataset.adminDefaultHtml || button.dataset.adminDefaultLabel || "";
    button.setAttribute(
      "href",
      button.dataset.adminDefaultHref || "admin-login.html",
    );
    button.dataset.adminState = "guest";
    const defaultLabel = button.dataset.adminDefaultLabel || "Admin";
    button.setAttribute("aria-label", defaultLabel);
    button.removeAttribute("title");
  }

  function renderOpenAuthButton(button, label, isSignedIn) {
    if (!button) return;
    const shouldStayVisibleWhenSignedIn =
      button.dataset.authDisplay === "member-label";

    if (isSignedIn) {
      if (!shouldStayVisibleWhenSignedIn) {
        button.hidden = true;
        button.classList.remove("auth-user-button");
        button.dataset.authState = "hidden";
        button.removeAttribute("title");
        return;
      }

      button.hidden = false;
      button.textContent = label;
      button.classList.add("auth-user-button");
      button.dataset.authState = "member";
      button.setAttribute("aria-label", `Signed in as ${label}`);
      button.title = label;
      return;
    }

    button.hidden = false;
    button.innerHTML =
      button.dataset.authDefaultHtml ||
      button.dataset.authDefaultLabel ||
      "Member Sign-In";
    button.classList.remove("auth-user-button");
    button.dataset.authState = "guest";
    const defaultLabel =
      button.dataset.authDefaultLabel ||
      button.textContent.trim() ||
      "Member Sign-In";
    button.setAttribute("aria-label", defaultLabel);
    button.removeAttribute("title");
  }

  function logoutCurrentSession(showMessage = true) {
    clearSession();
    updateAuthUI();
    ui.authModal?.closeModal?.();

    if (ui.prayerFormContainer && ui.loginWall) {
      ui.prayerFormContainer.style.display = "none";
      ui.loginWall.style.display = "block";
    }

    if (ui.counselingFormContainer && ui.loginWall) {
      ui.counselingFormContainer.style.display = "none";
      ui.loginWall.style.display = "block";
    }

    if (ui.formMessage) {
      ui.formMessage.textContent = "";
      ui.formMessage.className = "auth-message";
    }

    loadResources();
    loadAllMaterials();

    if (showMessage) {
      notify("You have been logged out.", "success");
    }
  }

  function parseIsoDateParts(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || "").trim());
    if (!match) return null;

    return {
      year: Number(match[1]),
      month: Number(match[2]),
      day: Number(match[3]),
    };
  }

  function getDatePartsInTimeZone(date, timeZone = MINISTRY_TIME_ZONE) {
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(date);
    const values = {};

    parts.forEach((part) => {
      if (
        part.type === "year" ||
        part.type === "month" ||
        part.type === "day"
      ) {
        values[part.type] = Number(part.value);
      }
    });

    if (!values.year || !values.month || !values.day) {
      return null;
    }

    return values;
  }

  function getDayNumberFromParts(parts) {
    return Math.floor(
      Date.UTC(parts.year, parts.month - 1, parts.day) /
        DAILY_BIBLE_READING_DAY_MS,
    );
  }

  function formatBibleReadingDate(date) {
    return new Intl.DateTimeFormat("en-US", {
      timeZone: MINISTRY_TIME_ZONE,
      weekday: "long",
      month: "long",
      day: "numeric",
      year: "numeric",
    }).format(date);
  }

  function getDailyBibleReading(date = new Date()) {
    const anchorIndex = DAILY_BIBLE_CHAPTER_INDEX.get(
      DAILY_BIBLE_READING_ANCHOR.reference.toLowerCase(),
    );
    if (!Number.isFinite(anchorIndex) || !DAILY_BIBLE_CHAPTERS.length) {
      return null;
    }

    const targetDateParts = getDatePartsInTimeZone(date);
    const anchorDateParts = parseIsoDateParts(DAILY_BIBLE_READING_ANCHOR.date);
    if (!targetDateParts || !anchorDateParts) {
      return null;
    }

    const daysSinceAnchor =
      getDayNumberFromParts(targetDateParts) -
      getDayNumberFromParts(anchorDateParts);
    const totalChapters = DAILY_BIBLE_CHAPTERS.length;
    const chapterIndex =
      (((anchorIndex + daysSinceAnchor) % totalChapters) + totalChapters) %
      totalChapters;
    const chapter = DAILY_BIBLE_CHAPTERS[chapterIndex];
    const url =
      `https://www.biblegateway.com/passage/?search=${encodeURIComponent(chapter.reference)}` +
      `&version=${DAILY_BIBLE_READING_ANCHOR.version}`;

    return {
      ...chapter,
      url,
      dateLabel: formatBibleReadingDate(date),
      summary:
        "Read prayerfully, note what stands out, and carry one clear insight into prayer and community conversation.",
      focus:
        `Read ${chapter.reference} slowly. Notice what it reveals about God, ` +
        "the choices being made, and one step of obedience for today.",
    };
  }

  function setupDailyBibleReading() {
    const reading = getDailyBibleReading();
    if (!reading) return;

    document
      .querySelectorAll("[data-daily-bible-reference]")
      .forEach((element) => {
        const prefix = element.getAttribute("data-daily-bible-prefix") || "";
        element.textContent = `${prefix}${reading.reference}`;
      });

    document.querySelectorAll("[data-daily-bible-link]").forEach((element) => {
      element.setAttribute("href", reading.url);
    });

    document.querySelectorAll("[data-daily-bible-date]").forEach((element) => {
      element.textContent = reading.dateLabel;
    });

    document
      .querySelectorAll("[data-daily-bible-summary]")
      .forEach((element) => {
        element.textContent = reading.summary;
      });

    document.querySelectorAll("[data-daily-bible-focus]").forEach((element) => {
      element.textContent = reading.focus;
    });
  }

  function setupScrollHeader() {
    if (!ui.header) return;

    const handleScroll = () => {
      if (window.scrollY > 20) {
        ui.header.classList.add("scrolled");
      } else {
        ui.header.classList.remove("scrolled");
      }
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
  }

  function setupMobileNav() {
    if (!ui.navToggle || !ui.mainNav) return;

    // Inject scrolling fix for mobile navigation panel
    const injectScrollFix = () => {
      if (document.getElementById("mobile-nav-scroll-fix")) return;
      const style = document.createElement("style");
      style.id = "mobile-nav-scroll-fix";
      style.textContent = `
        @media (max-width: 1120px) {
          nav.main-nav.open {
            display: flex !important;
            flex-direction: column !important;
            overflow-y: auto !important;
            max-height: 100dvh !important;
            height: auto !important;
            overscroll-behavior: contain;
            -webkit-overflow-scrolling: touch !important;
          }
        }
      `;
      document.head.appendChild(style);
    };
    injectScrollFix();

    const getHomeSectionHref = (hash) =>
      document.body.classList.contains("landing-home")
        ? hash
        : `index.html${hash}`;

    const buildSharedMobilePanelMarkup = () => `
      <div class="mobile-nav-group">
        <p class="mobile-nav-title">Ministry</p>
        <a href="${getHomeSectionHref("#home")}" class="mobile-nav-link">
          <i class="fa-solid fa-house"></i> Home
        </a>
        <a href="${getHomeSectionHref("#about")}" class="mobile-nav-link">
          <i class="fa-solid fa-church"></i> About Ministry
        </a>
        <a href="${getHomeSectionHref("#services")}" class="mobile-nav-link">
          <i class="fa-solid fa-compass"></i> What We Do
        </a>
        <a href="${getHomeSectionHref("#support")}" class="mobile-nav-link">
          <i class="fa-solid fa-hand-holding-heart"></i> Support Ministry
        </a>
        <a href="${getHomeSectionHref("#contact")}" class="mobile-nav-link">
          <i class="fa-solid fa-handshake"></i> Contact
        </a>
      </div>
      <div class="mobile-nav-group">
        <p class="mobile-nav-title">Resources</p>
        <a href="all-materials.html" class="mobile-nav-link">
          <i class="fa-solid fa-book-bible"></i> All Materials
        </a>
        <a href="bible-reading.html" class="mobile-nav-link">
          <i class="fa-solid fa-book-open"></i> Bible Reading
        </a>
        <a href="devotion.html" class="mobile-nav-link">
          <i class="fa-solid fa-fire-flame-curved"></i> Devotion
        </a>
        <a href="daily-promise.html" class="mobile-nav-link">
          <i class="fa-solid fa-star"></i> Daily Promise
        </a>
        <a href="community.html" class="mobile-nav-link">
          <i class="fa-solid fa-users"></i> Community
        </a>
      </div>
      <div class="mobile-nav-group">
        <p class="mobile-nav-title">Care &amp; Support</p>
        <a href="prayer.html" class="mobile-nav-link" data-protected-section>
          <i class="fa-solid fa-hands-praying"></i> Prayer
        </a>
        <a href="counseling.html" class="mobile-nav-link" data-protected-section>
          <i class="fa-solid fa-user-doctor"></i> Counseling
        </a>
        <a href="index-youth.html" class="mobile-nav-link">
          <i class="fa-solid fa-right-left"></i> Youth Version
        </a>
        <a
          href="https://www.youtube.com/channel/UCFp25-UmkyXpp6oBRxJZ3oQ"
          target="_blank"
          rel="noopener noreferrer"
          class="mobile-nav-link mobile-nav-link--youtube">
          <i class="fa-brands fa-youtube"></i> YouTube
        </a>
      </div>
    `;

    const ensureSharedMobilePanel = () => {
      ui.mainNav.classList.add("has-shared-mobile-panel");

      const panel =
        ui.mainNav.querySelector(".mobile-nav-panel") ||
        document.createElement("div");
      panel.className = "mobile-nav-panel";
      panel.innerHTML = buildSharedMobilePanelMarkup();

      if (!panel.parentElement) {
        ui.mainNav.insertBefore(
          panel,
          ui.mainNav.querySelector(".mobile-nav-actions"),
        );
      }

      ui.protectedSectionLinks = Array.from(
        document.querySelectorAll("[data-protected-section]"),
      );
    };

    ensureSharedMobilePanel();

    const syncMenuState = (isOpen) => {
      ui.mainNav.classList.toggle("open", isOpen);
      ui.navToggle.setAttribute("aria-expanded", String(isOpen));
      ui.navToggle.setAttribute(
        "aria-label",
        isOpen ? "Close Menu" : "Toggle Menu",
      );
      ui.navOverlay?.classList.toggle("open", isOpen);
      ui.navOverlay?.setAttribute("aria-hidden", String(!isOpen));
      document.body.classList.toggle("nav-open", isOpen);
    };

    const closeMenu = () => {
      syncMenuState(false);
      ui.navDropdownMenu?.classList.remove("open");
      ui.navDropdownTrigger?.setAttribute("aria-expanded", "false");
    };

    ui.navToggle.setAttribute("aria-expanded", "false");
    ui.navToggle.setAttribute("aria-controls", "mainNav");
    ui.navToggle.setAttribute("type", "button");
    ui.navOverlay?.setAttribute("aria-hidden", "true");

    ui.navToggle.addEventListener("click", (event) => {
      event.stopImmediatePropagation();
      event.preventDefault?.();
      syncMenuState(!ui.mainNav.classList.contains("open"));
    });

    ui.navToggle.addEventListener(
      "touchstart",
      (event) => {
        event.stopImmediatePropagation();
      },
      { passive: true },
    );

    ui.mainNav.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        closeMenu();
        trackEvent("nav_click", {
          label: link.textContent?.trim() || "navigation",
        });
      });
    });

    document.addEventListener("click", (event) => {
      if (!ui.mainNav.classList.contains("open")) return;

      const target = event.target;
      if (ui.mainNav.contains(target) || ui.navToggle.contains(target)) return;

      closeMenu();
    });

    ui.navOverlay?.addEventListener("click", closeMenu);

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && ui.mainNav.classList.contains("open")) {
        closeMenu();
      }
    });

    window.addEventListener("resize", () => {
      if (window.innerWidth > 1120) {
        closeMenu();
      }
    });
  }

  function setupNavDropdown() {
    const trigger = ui.navDropdownTrigger;
    const menu = ui.navDropdownMenu;
    if (!trigger || !menu) return;

    const closeMenu = () => {
      menu.classList.remove("open");
      trigger.setAttribute("aria-expanded", "false");
    };

    trigger.setAttribute("aria-expanded", "false");

    trigger.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const nextOpen = !menu.classList.contains("open");
      menu.classList.toggle("open", nextOpen);
      trigger.setAttribute("aria-expanded", String(nextOpen));
    });

    menu.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", closeMenu);
    });

    document.addEventListener("click", (event) => {
      if (!menu.classList.contains("open")) return;
      const target = event.target;
      if (menu.contains(target) || trigger.contains(target)) return;
      closeMenu();
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeMenu();
      }
    });
  }

  function setupActiveNavTracking() {
    const navLinks = Array.from(document.querySelectorAll(".main-nav a"));
    const sectionMap = navLinks
      .map((link) => {
        const href = link.getAttribute("href") || "";
        if (!href.startsWith("#")) return null;
        const section = document.querySelector(href);
        if (!section) return null;
        return { link, section };
      })
      .filter(Boolean);

    if (!sectionMap.length || !("IntersectionObserver" in window)) {
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;

          const found = sectionMap.find(
            (item) => item.section === entry.target,
          );
          if (!found) return;

          navLinks.forEach((link) => link.classList.remove("active"));
          found.link.classList.add("active");
        });
      },
      {
        rootMargin: "-45% 0px -45% 0px",
        threshold: 0.01,
      },
    );

    sectionMap.forEach((item) => observer.observe(item.section));
  }

  function setupRevealAnimations() {
    const targets = document.querySelectorAll("[data-reveal]:not(.revealed)");
    if (!targets.length) return;
    if (!("IntersectionObserver" in window)) {
      targets.forEach((item) => item.classList.add("revealed"));
      return;
    }

    const observer = new IntersectionObserver(
      (entries, obs) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("revealed");
          obs.unobserve(entry.target);
        });
      },
      {
        threshold: 0.14,
        rootMargin: "0px 0px -40px 0px",
      },
    );

    targets.forEach((item, index) => {
      item.style.transitionDelay = `${Math.min(index * 50, 320)}ms`;
      observer.observe(item);
    });
  }

  function setupModal() {
    const getCurrentAuthRedirectTarget = () =>
      `${window.location.pathname}${window.location.search}${window.location.hash}`;

    const handleAuthButtonClick = (button, openModal = null) => {
      if (button.dataset.authState === "member") {
        return;
      }

      const mode = button.dataset.openAuthMode || "login";

      if (openModal) {
        openModal(mode);
        return;
      }

      redirectToAuthEntryPage(getCurrentAuthRedirectTarget());
    };

    const wireOpenAuthButtons = (openModal = null) => {
      ui.openAuthBtns.forEach((button) => {
        button.addEventListener("click", () => {
          handleAuthButtonClick(button, openModal);
        });
      });
      ui.resourceLoginBtn?.addEventListener("click", () => {
        if (openModal) {
          openModal("login");
          return;
        }
        redirectToAuthEntryPage(getCurrentAuthRedirectTarget());
      });
      ui.logoutBtn?.addEventListener("click", () => {
        logoutCurrentSession();
      });
    };

    if (!ui.authModal) {
      wireOpenAuthButtons();
      return;
    }

    const open = (mode = "login") => {
      switchAuthMode(mode);
      ui.authModal.classList.add("open");
      ui.authModal.setAttribute("aria-hidden", "false");
      ui.mainNav?.classList.remove("open");
      ui.navToggle?.setAttribute("aria-expanded", "false");
      ui.navOverlay?.classList.remove("open");
      document.body.classList.remove("nav-open");
      focusAuthField();
    };

    const close = () => {
      ui.authModal.classList.remove("open");
      ui.authModal.setAttribute("aria-hidden", "true");
      setAuthMessage("");
    };

    switchAuthMode("login");

    wireOpenAuthButtons(open);
    ui.authModeButtons.forEach((button) => {
      button.addEventListener("click", () => {
        switchAuthMode(button.dataset.authMode || "login");
      });
    });
    ui.closeAuthBtn?.addEventListener("click", close);

    ui.authModal.addEventListener("click", (event) => {
      if (event.target === ui.authModal) {
        close();
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        close();
      }
    });

    ui.authModal.closeModal = close;
    ui.authModal.openModal = open;
  }

  function switchAuthMode(mode = "login") {
    const allowedModes = new Set(["login", "register", "recover"]);
    const nextMode = allowedModes.has(mode) ? mode : "login";
    state.authMode = nextMode;

    const authText = {
      login: {
        title: "Member Sign-In",
        subtitle: "Sign in to access prayer and counseling sections.",
      },
      register: {
        title: "Create Member Account",
        subtitle: "Create an account to access prayer and counseling sections.",
      },
      recover: {
        title: "Recover Password",
        subtitle:
          "Request a recovery code, then set a new password for your account.",
      },
    };

    ui.authViews.forEach((view) => {
      view.hidden = view.dataset.authView !== nextMode;
    });

    ui.authTabs.forEach((tab) => {
      const active = tab.dataset.authMode === nextMode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });

    if (ui.authModalTitle) {
      ui.authModalTitle.textContent = authText[nextMode].title;
    }
    if (ui.authModalSubtitle) {
      ui.authModalSubtitle.textContent = authText[nextMode].subtitle;
    }

    setAuthMessage("");
    focusAuthField();
  }

  function focusAuthField() {
    const focusByMode = {
      login: ui.loginEmail,
      register: ui.registerUsername,
      recover: ui.recoverEmail,
    };

    requestAnimationFrame(() => {
      focusByMode[state.authMode]?.focus?.();
    });
  }

  function setupProtectedSectionLinks() {
    if (!ui.protectedSectionLinks.length) return;

    ui.protectedSectionLinks.forEach((link) => {
      link.addEventListener("click", async (event) => {
        event.preventDefault();

        if (state.token && !state.user) {
          await hydrateSession();
        }

        if (state.token && state.user) {
          window.location.href = link.href;
          return;
        }

        const redirectTarget = link.getAttribute("href") || "prayer.html";
        setPostAuthRedirect(redirectTarget);

        if (ui.authModal?.openModal) {
          ui.authModal.openModal("login");
          setAuthMessage("Sign in to access this section.", false);
          return;
        }

        redirectToAuthEntryPage(redirectTarget);
      });
    });
  }

  function handleAuthEntryIntent() {
    if (!ui.authModal?.openModal) return;

    const params = new URLSearchParams(window.location.search);
    const mode = params.get("openAuth");
    const redirect = params.get("redirect");

    if (redirect) {
      setPostAuthRedirect(redirect);
    }

    if (mode) {
      const allowedModes = new Set(["login", "register", "recover"]);
      const resolvedMode = allowedModes.has(mode) ? mode : "login";
      ui.authModal.openModal(resolvedMode);
    }

    if (mode || redirect) {
      const cleanUrl = `${window.location.pathname}${window.location.hash || ""}`;
      window.history.replaceState({}, "", cleanUrl);
    }
  }

  function setupContactForm() {
    if (!ui.contactForm) return;

    ui.contactForm.addEventListener("submit", (event) => {
      event.preventDefault();

      const name = ui.contactName?.value.trim();
      const email = ui.contactEmail?.value.trim();
      const subject = ui.contactSubject?.value.trim();
      const message = ui.contactMessage?.value.trim();

      if (!name || !email || !subject || !message) {
        notify("Please complete all contact fields.", "error");
        return;
      }

      const body = [`Name: ${name}`, `Email: ${email}`, "", message].join("\n");

      const mailtoUrl = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
      window.location.href = mailtoUrl;
      trackEvent("contact_email_prepare", { subject });

      ui.contactForm.reset();
      notify("Opening your email app to send this message.", "success");
    });
  }

  function buildWhatsAppSupportUrl(phone, message) {
    const digits = String(phone || "").replace(/[^\d]/g, "");
    if (!digits) return "";
    const text = encodeURIComponent(message || "");
    return text
      ? `https://wa.me/${digits}?text=${text}`
      : `https://wa.me/${digits}`;
  }

  function getSupportPaymentUrl(config = {}) {
    const configuredPaymentLink = String(config.payment_link || "").trim();
    if (configuredPaymentLink) {
      return configuredPaymentLink;
    }

    if (onSupportPaymentPage) {
      return "";
    }

    return SUPPORT_PAYMENT_PAGE;
  }

  function applySupportConfig(config = {}) {
    supportState.config = {
      ...supportState.config,
      ...config,
    };

    const resolvedConfig = supportState.config;
    const paymentLink = String(resolvedConfig.payment_link || "").trim();
    const supportPaymentUrl = getSupportPaymentUrl(resolvedConfig);
    const whatsappUrl = buildWhatsAppSupportUrl(
      resolvedConfig.support_whatsapp,
      "Hello, I would like to support the ministry.",
    );
    const bankName =
      String(resolvedConfig.bank_name || "").trim() ||
      "Add your bank name from the admin panel";
    const accountName =
      String(resolvedConfig.account_name || "").trim() ||
      "Add your account name from the admin panel";
    const accountNumber =
      String(resolvedConfig.account_number || "").trim() ||
      "Add your account number from the admin panel";
    const supportEmail =
      String(resolvedConfig.support_email || "").trim() ||
      "admin@spiritualcenter.com";
    const currency = String(resolvedConfig.currency || "NGN")
      .trim()
      .toUpperCase();

    if (ui.supportHeading) {
      ui.supportHeading.textContent =
        resolvedConfig.heading || "Support the Ministry";
    }

    if (ui.supportIntro) {
      ui.supportIntro.textContent =
        resolvedConfig.intro ||
        "Your support helps sustain biblical teaching, prayer care, counseling, outreach, and ministry media.";
    }

    if (ui.supportCurrencyBadge) {
      ui.supportCurrencyBadge.textContent = currency || "NGN";
    }

    if (ui.supportBankName) {
      ui.supportBankName.textContent = bankName;
    }

    if (ui.supportAccountName) {
      ui.supportAccountName.textContent = accountName;
    }

    if (ui.supportAccountNumber) {
      ui.supportAccountNumber.textContent = accountNumber;
    }

    if (ui.supportPaymentNote) {
      ui.supportPaymentNote.textContent =
        resolvedConfig.payment_note ||
        "After sending your support, reach the ministry through WhatsApp or email with your transfer details so it can be confirmed quickly.";
    }

    if (ui.supportEmailLink) {
      ui.supportEmailLink.textContent = supportEmail;
      ui.supportEmailLink.href = `mailto:${supportEmail}`;
    }

    if (ui.supportWhatsappLink) {
      ui.supportWhatsappLink.href = whatsappUrl || "#support";
      ui.supportWhatsappLink.hidden = !whatsappUrl;
    }

    if (ui.supportPaymentLink) {
      const shouldShowPaymentLink = Boolean(supportPaymentUrl);
      ui.supportPaymentLink.hidden = !shouldShowPaymentLink;
      ui.supportPaymentLink.href = shouldShowPaymentLink
        ? supportPaymentUrl
        : "#support";
      if (shouldShowPaymentLink) {
        ui.supportPaymentLink.target = paymentLink ? "_blank" : "_self";
        ui.supportPaymentLink.rel = paymentLink ? "noopener noreferrer" : "";
      }
    }
  }

  async function loadSupportConfig() {
    if (!ui.supportHeading) return;

    try {
      const response = await fetch(`${API_BASE}/support/config`);
      const data = await response
        .json()
        .catch(() => ({ error: "Unexpected response format" }));

      if (!response.ok || !data?.success || !data.support) {
        throw new Error(data?.error || "Failed to load support details");
      }

      applySupportConfig(data.support);
    } catch (error) {
      console.error("Support config load error:", error);
      applySupportConfig(supportState.config);
    }
  }

  function setupLoginForm() {
    if (!ui.loginForm) return;

    ui.loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const email = ui.loginEmail?.value.trim();
      const password = ui.loginPassword?.value;

      if (!email || !password) {
        setAuthMessage("Please enter email/username and password.", true);
        return;
      }

      setAuthLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (!response.ok || !data?.token) {
          throw new Error(data?.error || "Unable to sign in.");
        }

        state.token = data.token;
        state.user = data.user || null;

        localStorage.setItem("authToken", data.token);
        persistMemberDisplayName(data.user, email);

        updateAuthUI();
        loadResources();
        trackEvent("login_success", { method: "email_password" });

        setAuthMessage("Sign-in successful.", false);
        notify("You are signed in successfully.", "success");

        if (redirectAfterAuthIfNeeded()) {
          return;
        }

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.loginForm?.reset();
        }, 500);
      } catch (error) {
        trackEvent("login_failed", {
          reason: String(error.message || "unknown_error").slice(0, 120),
        });
        setAuthMessage(error.message || "Login failed.", true);
      } finally {
        setAuthLoading(false);
      }
    });
  }

  function setupRegisterForm() {
    if (!ui.registerForm) return;

    ui.registerForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const username = ui.registerUsername?.value.trim();
      const email = ui.registerEmail?.value.trim();
      const password = ui.registerPassword?.value || "";
      const confirmPassword = ui.registerConfirmPassword?.value || "";

      if (!username || !email || !password || !confirmPassword) {
        setAuthMessage("Please complete all registration fields.", true);
        return;
      }

      if (password.length < 8) {
        setAuthMessage("Password must be at least 8 characters long.", true);
        return;
      }

      if (password !== confirmPassword) {
        setAuthMessage("Password confirmation does not match.", true);
        return;
      }

      setRegisterLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            email,
            password,
            confirmPassword,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.error || "Unable to create account.");
        }

        if (data?.requires_approval || !data?.token) {
          const approvalMessage =
            data?.message ||
            "Registration submitted. An administrator will review your account.";

          ui.registerForm?.reset();
          switchAuthMode("login");
          setAuthMessage(approvalMessage, false);
          notify(approvalMessage, "success");
          trackEvent("register_pending_approval", {
            method: "email_password",
            role: data?.user?.role || "user",
          });
          return;
        }

        state.token = data.token;
        state.user = data.user || null;
        localStorage.setItem("authToken", data.token);
        persistMemberDisplayName(data.user, username || email);

        updateAuthUI();
        loadResources();
        notify("Registration successful. You are now signed in.", "success");
        setAuthMessage("Account created successfully.", false);
        trackEvent("register_success", { method: "email_password" });

        if (redirectAfterAuthIfNeeded()) {
          return;
        }

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.registerForm?.reset();
        }, 500);
      } catch (error) {
        trackEvent("register_failed", {
          reason: String(error.message || "unknown_error").slice(0, 120),
        });
        setAuthMessage(error.message || "Registration failed.", true);
      } finally {
        setRegisterLoading(false);
      }
    });
  }

  function setupRecoverForm() {
    if (!ui.recoverForm) return;

    ui.requestRecoveryBtn?.addEventListener("click", async () => {
      const email = ui.recoverEmail?.value.trim();
      if (!email) {
        setAuthMessage(
          "Enter your account email before requesting a code.",
          true,
        );
        return;
      }

      setRecoveryRequestLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/forgot-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.error || "Unable to request recovery code.");
        }

        if (data?.recovery_code && ui.recoverCode) {
          ui.recoverCode.value = data.recovery_code;
          setAuthMessage(
            "Recovery code generated. Use it now before it expires.",
            false,
          );
        } else {
          setAuthMessage(
            data?.message || "Recovery instructions have been sent.",
            false,
          );
        }
      } catch (error) {
        setAuthMessage(
          error.message || "Failed to request recovery code.",
          true,
        );
      } finally {
        setRecoveryRequestLoading(false);
      }
    });

    ui.recoverForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const email = ui.recoverEmail?.value.trim();
      const recoveryCode = ui.recoverCode?.value.trim();
      const newPassword = ui.recoverPassword?.value || "";
      const confirmPassword = ui.recoverConfirmPassword?.value || "";

      if (!email || !recoveryCode || !newPassword || !confirmPassword) {
        setAuthMessage("Please complete all password recovery fields.", true);
        return;
      }

      if (newPassword.length < 8) {
        setAuthMessage(
          "New password must be at least 8 characters long.",
          true,
        );
        return;
      }

      if (newPassword !== confirmPassword) {
        setAuthMessage("Password confirmation does not match.", true);
        return;
      }

      setRecoverSubmitLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/reset-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            recoveryCode,
            newPassword,
            confirmPassword,
          }),
        });

        const data = await response.json();

        if (!response.ok || !data?.token) {
          throw new Error(data?.error || "Failed to reset password.");
        }

        state.token = data.token;
        state.user = data.user || null;
        localStorage.setItem("authToken", data.token);
        persistMemberDisplayName(data.user, email);

        updateAuthUI();
        loadResources();
        notify("Password reset successful. You are signed in.", "success");
        setAuthMessage("Password reset successful.", false);
        trackEvent("password_reset_success", { source: "self_service" });

        if (redirectAfterAuthIfNeeded()) {
          return;
        }

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.recoverForm?.reset();
        }, 500);
      } catch (error) {
        trackEvent("password_reset_failed", {
          reason: String(error.message || "unknown_error").slice(0, 120),
        });
        setAuthMessage(error.message || "Password reset failed.", true);
      } finally {
        setRecoverSubmitLoading(false);
      }
    });
  }

  function setupPrayerPage() {
    if (!ui.prayerPageForm) return;

    wireSectionLoginButton("prayer.html");

    const setAuthorizedView = () => {
      if (ui.loginWall) ui.loginWall.style.display = "none";
      if (ui.prayerFormContainer)
        ui.prayerFormContainer.style.display = "block";
      prefillPrayerFormsFromUser();
    };

    const setBlockedView = () => {
      if (ui.loginWall) ui.loginWall.style.display = "block";
      if (ui.prayerFormContainer) ui.prayerFormContainer.style.display = "none";
    };

    const initPrayerAccess = async () => {
      if (!state.token) {
        setBlockedView();
        return;
      }

      await hydrateSession();
      if (state.user) {
        setAuthorizedView();
      } else {
        setBlockedView();
      }
    };

    initPrayerAccess();

    ui.prayerPageForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const name = ui.prayerPageName?.value.trim();
      const email = ui.prayerPageEmail?.value.trim();
      const whatsapp_number = ui.prayerPageWhatsapp?.value.trim();
      const request = ui.prayerPageRequest?.value.trim();
      const is_anonymous = ui.prayerPageAnonymous?.checked;

      if (!request || !whatsapp_number) {
        notify(
          "Please enter your prayer request and WhatsApp number.",
          "error",
        );
        return;
      }

      try {
        const response = await fetch(`${API_BASE}/prayer-requests`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${state.token}`,
          },
          body: JSON.stringify({
            name,
            email,
            whatsapp_number,
            request,
            is_anonymous,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.error || "Unable to submit prayer request.");
        }

        ui.prayerPageForm.reset();
        prefillPrayerFormsFromUser();
        notify("Prayer request submitted successfully.", "success");
        setSectionMessage("Your prayer request has been sent.", "success");
      } catch (error) {
        notify(error.message || "An error occurred.", "error");
        setSectionMessage(error.message || "An error occurred.", "error");
      }
    });

    ui.prayerBookingForm?.addEventListener("submit", async (event) => {
      event.preventDefault();

      const name = ui.prayerBookingName?.value.trim();
      const email = ui.prayerBookingEmail?.value.trim();
      const whatsapp_number = ui.prayerBookingWhatsapp?.value.trim();
      const availability = ui.prayerBookingAvailability?.value.trim();
      const focus = ui.prayerBookingFocus?.value.trim();

      if (!availability || !focus || !whatsapp_number) {
        notify(
          "Please complete booking availability, focus, and WhatsApp number.",
          "error",
        );
        return;
      }

      const request = [
        "Prayer Session Booking",
        `Preferred availability: ${availability}`,
        `Focus: ${focus}`,
      ].join("\n");

      try {
        const response = await fetch(`${API_BASE}/prayer-requests`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${state.token}`,
          },
          body: JSON.stringify({
            name,
            email,
            whatsapp_number,
            request,
            is_anonymous: false,
          }),
        });

        const data = await response.json();
        if (!response.ok) {
          throw new Error(data?.error || "Unable to book prayer session.");
        }

        ui.prayerBookingForm.reset();
        prefillPrayerFormsFromUser();
        notify("Prayer session booking submitted successfully.", "success");
        setSectionMessage(
          "Your prayer session booking has been sent.",
          "success",
        );
      } catch (error) {
        notify(error.message || "An error occurred.", "error");
        setSectionMessage(error.message || "An error occurred.", "error");
      }
    });
  }

  function setupCounselingPage() {
    if (!ui.counselingPageForm) return;

    wireSectionLoginButton("counseling.html");

    const setAuthorizedView = () => {
      if (ui.loginWall) ui.loginWall.style.display = "none";
      if (ui.counselingFormContainer)
        ui.counselingFormContainer.style.display = "block";
    };

    const setBlockedView = () => {
      if (ui.loginWall) ui.loginWall.style.display = "block";
      if (ui.counselingFormContainer)
        ui.counselingFormContainer.style.display = "none";
    };

    const initCounselingAccess = async () => {
      if (!state.token) {
        setBlockedView();
        return;
      }

      await hydrateSession();
      if (state.user) {
        setAuthorizedView();
      } else {
        setBlockedView();
      }
    };

    initCounselingAccess();

    ui.counselingPageForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const intent = ui.counselingIntent?.value || "";
      const counseling_type = ui.counselingType?.value;
      const whatsapp_number = ui.counselingWhatsapp?.value.trim();
      const description = ui.counselingDescription?.value.trim();
      const preferred_availability = ui.counselingAvailability?.value.trim();

      if (!intent || !counseling_type || !description || !whatsapp_number) {
        notify(
          "Please select request option, type, description, and WhatsApp number.",
          "error",
        );
        return;
      }

      const descriptionPrefix =
        intent === "booking"
          ? "[Counseling Session Booking]"
          : "[Counseling Request]";
      const descriptionPayload = `${descriptionPrefix}\n${description}`;

      try {
        const response = await fetch(`${API_BASE}/counseling-requests`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${state.token}`,
          },
          body: JSON.stringify({
            counseling_type,
            whatsapp_number,
            description: descriptionPayload,
            preferred_availability,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(
            data?.error || "Unable to submit counseling request.",
          );
        }

        ui.counselingPageForm.reset();
        const successMessage =
          intent === "booking"
            ? "Counseling session booking submitted successfully."
            : "Counseling request submitted successfully.";
        notify(successMessage, "success");
        setSectionMessage("Your submission has been sent.", "success");
      } catch (error) {
        notify(error.message || "An error occurred.", "error");
        setSectionMessage(error.message || "An error occurred.", "error");
      }
    });
  }

  function prefillPrayerFormsFromUser() {
    if (!state.user) return;
    const username = state.user.username || "";
    const email = state.user.email || "";

    if (ui.prayerPageName) ui.prayerPageName.value = username;
    if (ui.prayerPageEmail) ui.prayerPageEmail.value = email;
    if (ui.prayerBookingName) ui.prayerBookingName.value = username;
    if (ui.prayerBookingEmail) ui.prayerBookingEmail.value = email;
  }

  function setSectionMessage(text, tone = "success") {
    if (!ui.formMessage) return;
    ui.formMessage.textContent = text;
    ui.formMessage.className = `auth-message ${tone}`;
  }

  function wireSectionLoginButton(targetPath) {
    if (!ui.loginBtn) return;

    ui.loginBtn.addEventListener("click", () => {
      setPostAuthRedirect(targetPath);
      if (ui.authModal?.openModal) {
        ui.authModal.openModal("login");
        return;
      }
      redirectToAuthEntryPage(targetPath);
    });
  }

  function setAuthLoading(isLoading) {
    if (!ui.loginSubmitBtn) return;
    ui.loginSubmitBtn.disabled = isLoading;
    ui.loginSubmitBtn.textContent = isLoading ? "Signing In..." : "Sign In";
  }

  function setRegisterLoading(isLoading) {
    if (!ui.registerSubmitBtn) return;
    ui.registerSubmitBtn.disabled = isLoading;
    ui.registerSubmitBtn.textContent = isLoading
      ? "Creating Account..."
      : "Create Account";
  }

  function setRecoveryRequestLoading(isLoading) {
    if (!ui.requestRecoveryBtn) return;
    ui.requestRecoveryBtn.disabled = isLoading;
    ui.requestRecoveryBtn.textContent = isLoading
      ? "Generating Code..."
      : "Request Recovery Code";
  }

  function setRecoverSubmitLoading(isLoading) {
    if (!ui.recoverSubmitBtn) return;
    ui.recoverSubmitBtn.disabled = isLoading;
    ui.recoverSubmitBtn.textContent = isLoading
      ? "Resetting Password..."
      : "Reset Password";
  }

  function setAuthMessage(text, isError = false) {
    if (!ui.authMessage) return;
    ui.authMessage.textContent = text;
    ui.authMessage.className = "auth-message";
    if (text) {
      ui.authMessage.classList.add(isError ? "error" : "success");
    }
  }

  async function hydrateSession() {
    if (!state.token) return;

    try {
      const response = await fetch(`${API_BASE}/auth/validate`, {
        headers: {
          Authorization: `Bearer ${state.token}`,
        },
      });

      const data = await response.json();

      if (!response.ok || !data?.user) {
        throw new Error("Session expired");
      }

      state.user = data.user;
      persistMemberDisplayName(data.user);
      updateAuthUI();
    } catch (error) {
      clearSession();
      updateAuthUI();
    }
  }

  function clearSession() {
    state.token = null;
    state.user = null;

    localStorage.removeItem("authToken");
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminEmail");
    localStorage.removeItem("adminUsername");
    localStorage.removeItem("adminRole");
    localStorage.removeItem("isSuperAdmin");
    localStorage.removeItem(MEMBER_DISPLAY_NAME_KEY);
  }

  function updateAuthUI() {
    const hasStoredSession = Boolean(
      state.token ||
      localStorage.getItem("authToken") ||
      localStorage.getItem("adminToken"),
    );
    const loggedIn = Boolean(state.token && state.user);
    const resolvedDisplayName = loggedIn
      ? persistMemberDisplayName(state.user)
      : getStoredMemberDisplayName();
    const authButtonLabel = resolvedDisplayName || "Member";
    const adminSessionSummary = getAdminSessionSummary();

    document.documentElement.classList.toggle(
      "has-auth-session",
      hasStoredSession,
    );

    if (ui.userBadge) {
      ui.userBadge.hidden = !loggedIn;
    }

    if (ui.logoutBtn) {
      ui.logoutBtn.hidden = !loggedIn;
    }

    if (ui.resourceLoginBtn) {
      ui.resourceLoginBtn.hidden = hasStoredSession;
    }

    ui.openAuthBtns.forEach((button) => {
      renderOpenAuthButton(button, authButtonLabel, hasStoredSession);
    });

    ui.adminEntryButtons.forEach((button) => {
      renderAdminEntryButton(button, adminSessionSummary);
    });

    if (loggedIn) {
      const displayName = state.user.username || state.user.email || "Member";
      const role = state.user.role || "member";

      if (ui.userName) ui.userName.textContent = displayName;
      if (ui.userRole) ui.userRole.textContent = role;
      if (ui.userAvatar) {
        ui.userAvatar.textContent = displayName.charAt(0).toUpperCase();
      }
    }
  }

  function normalizeInternalRedirect(rawTarget) {
    if (!rawTarget) return "";

    try {
      const parsedUrl = new URL(rawTarget, window.location.origin);
      if (parsedUrl.origin !== window.location.origin) return "";

      const normalized = `${parsedUrl.pathname}${parsedUrl.search}${parsedUrl.hash}`;
      if (!normalized) return "";
      return normalized.startsWith("/") ? normalized.slice(1) : normalized;
    } catch {
      return "";
    }
  }

  function setPostAuthRedirect(targetPath) {
    const normalized = normalizeInternalRedirect(targetPath);
    if (!normalized) return;
    localStorage.setItem(POST_AUTH_REDIRECT_KEY, normalized);
  }

  function consumePostAuthRedirect() {
    const savedTarget = localStorage.getItem(POST_AUTH_REDIRECT_KEY) || "";
    localStorage.removeItem(POST_AUTH_REDIRECT_KEY);
    return normalizeInternalRedirect(savedTarget);
  }

  function redirectAfterAuthIfNeeded() {
    const target = consumePostAuthRedirect();
    if (!target) return false;
    window.location.href = target;
    return true;
  }

  function redirectToAuthEntryPage(targetPath = "") {
    const redirectTarget = normalizeInternalRedirect(targetPath);
    const entryPage = window.location.pathname
      .toLowerCase()
      .endsWith("index-youth.html")
      ? "index-youth.html"
      : "index.html";

    const params = new URLSearchParams({ openAuth: "login" });
    if (redirectTarget) {
      params.set("redirect", redirectTarget);
    }

    window.location.href = `${entryPage}?${params.toString()}`;
  }

  function buildMaterialsQuery(params = {}) {
    const searchParams = new URLSearchParams();
    const page = Number(params.page || 1);
    const limit = Number(params.limit || 20);
    const search = String(params.search || "").trim();
    const category = String(params.category || "").trim();
    const type = String(params.type || "").trim();

    searchParams.set("page", String(page));
    searchParams.set("limit", String(limit));

    if (search) searchParams.set("search", search);
    if (category) searchParams.set("category", category);
    if (type) searchParams.set("type", type);

    return searchParams.toString();
  }

  async function fetchMaterialsPage(params = {}, token = null) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const query = buildMaterialsQuery(params);
    const response = await fetch(`${API_BASE}/materials?${query}`, { headers });
    const data = await response
      .json()
      .catch(() => ({ error: "Unexpected server response format." }));
    return { response, data };
  }

  function normalizeMaterials(materials = []) {
    return materials.map((item) => ({
      title: item.title || "Untitled Material",
      description: item.description || "No description available.",
      category: item.category || "resource",
      type: item.type || "file",
      link: resolveFileUrl(item.file_url),
      fileUrl: item.file_url || "",
      youtubeUrl: item.youtube_url || item.youtubeUrl || "",
    }));
  }

  async function loadResources() {
    if (!ui.resourceGrid) return;

    setResourceNotice("Loading teachings...");
    ui.resourceGrid.innerHTML = "";

    try {
      let { response, data } = await fetchMaterialsPage(
        { limit: RESOURCE_MAX_LIMIT, page: 1 },
        state.token || null,
      );

      if ((response.status === 401 || response.status === 403) && state.token) {
        clearSession();
        updateAuthUI();
        ({ response, data } = await fetchMaterialsPage(
          { limit: RESOURCE_MAX_LIMIT, page: 1 },
          null,
        ));
      }

      if (response.status === 401 || response.status === 403) {
        setResourceNotice(
          "Uploaded materials are temporarily unavailable. Showing curated resources for now.",
          "warning",
        );
        resourceState.items = [...fallbackResources];
        resourceState.fromApi = false;
        resourceState.displayed = resourceState.items.length;
        resourceState.total = resourceState.items.length;
        if (ui.resourceViewAll) ui.resourceViewAll.hidden = true;
        renderResourceBatch();
        return;
      }

      if (!response.ok) {
        // Log error details for debugging
        console.error(
          "[Materials Fetch] API error:",
          response.status,
          data,
          `${API_BASE}/materials`,
        );
        throw new Error(data?.error || "Failed to load resources.");
      }
      if (!data || data.success !== true) {
        // Log error details for debugging
        console.error(
          "[Materials Fetch] Invalid response:",
          data,
          `${API_BASE}/materials`,
        );
        throw new Error("Invalid response from materials endpoint.");
      }

      const materials = Array.isArray(data.materials) ? data.materials : [];
      const total = Number(data?.pagination?.total || materials.length);
      if (!materials.length) {
        setResourceNotice(
          "No uploaded materials are available yet. Showing curated resources.",
          "warning",
        );
        resourceState.items = [...fallbackResources];
        resourceState.fromApi = false;
        resourceState.displayed = resourceState.items.length;
        resourceState.total = resourceState.items.length;
        if (ui.resourceViewAll) ui.resourceViewAll.hidden = true;
        renderResourceBatch();
        return;
      }

      const normalized = normalizeMaterials(materials);

      resourceState.items = normalized;
      resourceState.fromApi = true;
      resourceState.displayed = Math.min(RESOURCE_PAGE_SIZE, normalized.length);
      resourceState.total = total;
      renderResourceBatch();
      const showingCount = Math.min(total, normalized.length);
      const hasMoreThanLimit = total > normalized.length;
      if (ui.resourceViewAll) ui.resourceViewAll.hidden = !hasMoreThanLimit;
      setResourceNotice(
        hasMoreThanLimit
          ? `Latest ministry materials (${total} available). Showing the newest ${showingCount}. Visit All Materials to browse the full library.`
          : `Latest ministry materials (${total} available for all visitors).`,
        "success",
      );
    } catch (error) {
      // Log error details for debugging
      console.error(
        "[Materials Fetch] Exception:",
        error,
        `${API_BASE}/materials`,
      );
      setResourceNotice(
        "Unable to load uploaded materials at the moment. Showing curated resources.",
        "error",
      );
      resourceState.items = [...fallbackResources];
      resourceState.fromApi = false;
      resourceState.displayed = resourceState.items.length;
      resourceState.total = resourceState.items.length;
      if (ui.resourceViewAll) ui.resourceViewAll.hidden = true;
      renderResourceBatch();
    }
  }

  function renderResourceBatch() {
    const displayed = Math.min(
      resourceState.displayed,
      resourceState.items.length,
    );
    renderResources(
      resourceState.items.slice(0, displayed),
      resourceState.fromApi,
    );

    if (ui.resourceCount) {
      if (resourceState.fromApi && resourceState.items.length) {
        const total = Number(resourceState.total || resourceState.items.length);
        const baseText = `Showing ${displayed} of ${resourceState.items.length} materials`;
        ui.resourceCount.textContent =
          total > resourceState.items.length
            ? `${baseText} (total ${total})`
            : baseText;
      } else {
        ui.resourceCount.textContent = "";
      }
    }

    if (ui.resourceLoadMore) {
      ui.resourceLoadMore.hidden =
        !resourceState.fromApi || displayed >= resourceState.items.length;
    }
  }

  function setupResourceControls() {
    if (!ui.resourceLoadMore) return;
    ui.resourceLoadMore.addEventListener("click", () => {
      loadMoreResources();
    });
  }

  function loadMoreResources() {
    if (!resourceState.items.length) return;
    resourceState.displayed = Math.min(
      resourceState.displayed + RESOURCE_PAGE_SIZE,
      resourceState.items.length,
    );
    renderResourceBatch();
  }

  function setupAllMaterialsPage() {
    if (!ui.allMaterialsGrid) return;

    const params = new URLSearchParams(window.location.search);
    const initialSearch = String(params.get("search") || "").trim();
    const initialCategory = String(params.get("category") || "").trim();
    const initialType = String(params.get("type") || "").trim();
    const initialPage = Number.parseInt(params.get("page") || "1", 10);

    if (initialSearch && ui.allMaterialsSearch) {
      ui.allMaterialsSearch.value = initialSearch;
      allMaterialsState.search = initialSearch;
    }
    if (initialCategory && ui.allMaterialsCategory) {
      ui.allMaterialsCategory.value = initialCategory;
      allMaterialsState.category = initialCategory;
    }
    if (initialType && ui.allMaterialsType) {
      ui.allMaterialsType.value = initialType;
      allMaterialsState.type = initialType;
    }
    if (Number.isFinite(initialPage) && initialPage > 0) {
      allMaterialsState.page = initialPage;
    }

    ui.allMaterialsForm?.addEventListener("submit", (event) => {
      event.preventDefault();
      applyAllMaterialsFilters();
    });

    ui.allMaterialsClear?.addEventListener("click", () => {
      clearAllMaterialsFilters();
    });

    ui.allMaterialsPrev?.addEventListener("click", () => {
      if (allMaterialsState.page <= 1) return;
      allMaterialsState.page -= 1;
      loadAllMaterials();
    });

    ui.allMaterialsNext?.addEventListener("click", () => {
      if (allMaterialsState.page >= allMaterialsState.pages) return;
      allMaterialsState.page += 1;
      loadAllMaterials();
    });
  }

  function applyAllMaterialsFilters() {
    allMaterialsState.search = ui.allMaterialsSearch?.value.trim() || "";
    allMaterialsState.category = ui.allMaterialsCategory?.value.trim() || "";
    allMaterialsState.type = ui.allMaterialsType?.value.trim() || "";
    allMaterialsState.page = 1;
    loadAllMaterials();
  }

  function clearAllMaterialsFilters() {
    if (ui.allMaterialsSearch) ui.allMaterialsSearch.value = "";
    if (ui.allMaterialsCategory) ui.allMaterialsCategory.value = "";
    if (ui.allMaterialsType) ui.allMaterialsType.value = "";
    allMaterialsState.search = "";
    allMaterialsState.category = "";
    allMaterialsState.type = "";
    allMaterialsState.page = 1;
    loadAllMaterials();
  }

  function setAllMaterialsNotice(text, tone = "") {
    if (!ui.allMaterialsNotice) return;

    ui.allMaterialsNotice.textContent = text;
    ui.allMaterialsNotice.className = "resource-notice";

    if (tone === "warning") ui.allMaterialsNotice.classList.add("is-warning");
    if (tone === "error") ui.allMaterialsNotice.classList.add("is-error");
    if (tone === "success") ui.allMaterialsNotice.classList.add("is-success");
  }

  function updateAllMaterialsPagination(displayedCount) {
    const total = Number(allMaterialsState.total || 0);
    const pages = Number(allMaterialsState.pages || 1);
    const page = Number(allMaterialsState.page || 1);

    if (ui.allMaterialsPage) {
      if (!displayedCount) {
        ui.allMaterialsPage.textContent = total
          ? `Page ${page} of ${pages} - No materials to display`
          : "No materials found";
      } else {
        const start = (page - 1) * allMaterialsState.limit + 1;
        const end = Math.min(start + displayedCount - 1, total || start);
        ui.allMaterialsPage.textContent = total
          ? `Page ${page} of ${pages} - Showing ${start} to ${end} of ${total} materials`
          : `Showing ${displayedCount} materials`;
      }
    }

    if (ui.allMaterialsPrev) {
      ui.allMaterialsPrev.disabled = page <= 1;
    }
    if (ui.allMaterialsNext) {
      ui.allMaterialsNext.disabled = page >= pages;
    }
  }

  async function loadAllMaterials() {
    if (!ui.allMaterialsGrid || allMaterialsState.loading) return;

    allMaterialsState.loading = true;
    setAllMaterialsNotice("Loading materials...");
    ui.allMaterialsGrid.innerHTML = "";
    allMaterialsState.total = 0;
    allMaterialsState.pages = 1;

    const requestParams = {
      page: allMaterialsState.page,
      limit: allMaterialsState.limit,
      search: allMaterialsState.search,
      category: allMaterialsState.category,
      type: allMaterialsState.type,
    };

    try {
      let { response, data } = await fetchMaterialsPage(
        requestParams,
        state.token || null,
      );

      if ((response.status === 401 || response.status === 403) && state.token) {
        clearSession();
        updateAuthUI();
        ({ response, data } = await fetchMaterialsPage(requestParams, null));
      }

      if (response.status === 401 || response.status === 403) {
        setAllMaterialsNotice(
          "Materials are temporarily unavailable. Please try again soon.",
          "warning",
        );
        updateAllMaterialsPagination(0);
        return;
      }

      if (!response.ok) {
        throw new Error(data?.error || "Failed to load materials.");
      }
      if (!data || data.success !== true) {
        throw new Error("Invalid response from materials endpoint.");
      }

      const materials = Array.isArray(data.materials) ? data.materials : [];
      const total = Number(data?.pagination?.total || 0);
      const pages = Number(data?.pagination?.pages || 1);
      const normalized = normalizeMaterials(materials);

      allMaterialsState.total = total;
      allMaterialsState.pages = pages || 1;

      if (!normalized.length) {
        setAllMaterialsNotice(
          "No materials matched your filters. Try a different search.",
          "warning",
        );
        updateAllMaterialsPagination(0);
        return;
      }

      renderResources(normalized, true, ui.allMaterialsGrid);
      setAllMaterialsNotice(
        allMaterialsState.search ||
          allMaterialsState.category ||
          allMaterialsState.type
          ? "Showing results based on your filters."
          : "Browse the complete ministry library below.",
        "success",
      );
      updateAllMaterialsPagination(normalized.length);
    } catch (error) {
      setAllMaterialsNotice(
        "Unable to load materials at the moment. Please try again soon.",
        "error",
      );
      updateAllMaterialsPagination(0);
    } finally {
      allMaterialsState.loading = false;
    }
  }

  function resolveFileUrl(fileUrl) {
    if (!fileUrl) return "#contact";
    if (/^https?:\/\//i.test(fileUrl)) return fileUrl;
    const normalizedPath = String(fileUrl)
      .replace(/\\/g, "/")
      .replace(/^\.?\/*/, "");
    if (!normalizedPath) return "#contact";
    return `${BACKEND_ORIGIN}/${normalizedPath}`;
  }

  function getMediaKind(resource) {
    const typeToken = String(resource.type || "").toLowerCase();
    const categoryToken = String(resource.category || "").toLowerCase();
    const linkToken = String(resource.link || "").toLowerCase();

    if (
      typeToken.includes("image") ||
      typeToken.includes("photo") ||
      categoryToken.includes("image") ||
      categoryToken.includes("photo") ||
      /\.(jpg|jpeg|png|gif|webp|avif|svg)(\?|#|$)/i.test(linkToken)
    ) {
      return "image";
    }

    if (
      typeToken.includes("video") ||
      categoryToken.includes("video") ||
      /\.(mp4|webm|ogg|mov|m4v|mkv)(\?|#|$)/i.test(linkToken)
    ) {
      return "video";
    }

    if (
      typeToken.includes("audio") ||
      typeToken.includes("music") ||
      categoryToken.includes("audio") ||
      categoryToken.includes("music") ||
      /\.(mp3|wav|ogg|m4a|aac|flac)(\?|#|$)/i.test(linkToken)
    ) {
      return "audio";
    }

    if (
      typeToken.includes("document") ||
      typeToken.includes("writeup") ||
      categoryToken.includes("document") ||
      /\.(pdf|doc|docx|ppt|pptx|xls|xlsx|txt|zip|rar)(\?|#|$)/i.test(linkToken)
    ) {
      return "document";
    }

    return "file";
  }

  function renderPreviewPlaceholder(iconClass, label) {
    return `
      <div class="resource-player-wrap">
        <div class="resource-preview-placeholder" aria-hidden="true">
          <i class="${iconClass} resource-preview-icon"></i>
          <span class="resource-preview-label">${label}</span>
        </div>
      </div>
    `;
  }

  function renderMediaPreview(mediaKind, safeSrc, safeTitle) {
    const hasMediaSource = safeSrc && safeSrc !== "#contact";

    if (mediaKind === "image") {
      if (!hasMediaSource) {
        return renderPreviewPlaceholder("fa-regular fa-image", "Image Preview");
      }

      return `
        <div class="resource-player-wrap">
          <img
            class="resource-player resource-player-image"
            src="${safeSrc}"
            alt="${safeTitle}"
            loading="lazy"
            decoding="async" />
        </div>
      `;
    }

    if (mediaKind === "video") {
      if (!hasMediaSource) {
        return renderPreviewPlaceholder("fa-solid fa-video", "Video Preview");
      }

      return `
        <div class="resource-player-wrap">
          <video class="resource-player resource-player-video" controls preload="metadata">
            <source src="${safeSrc}" />
            Your browser does not support video playback.
          </video>
        </div>
      `;
    }

    if (mediaKind === "audio") {
      if (!hasMediaSource) {
        return renderPreviewPlaceholder(
          "fa-solid fa-headphones",
          "Audio Preview",
        );
      }

      return `
        <div class="resource-player-wrap">
          <audio class="resource-player resource-player-audio" controls preload="metadata" title="${safeTitle}">
            <source src="${safeSrc}" />
            Your browser does not support audio playback.
          </audio>
        </div>
      `;
    }

    if (mediaKind === "document") {
      return renderPreviewPlaceholder(
        "fa-regular fa-file-lines",
        "Document Preview",
      );
    }

    return renderPreviewPlaceholder("fa-regular fa-file", "Material Preview");
  }

  function resolveResourceLinkLabel(mediaKind, hasMediaSource, fromApi) {
    if (mediaKind === "image" && hasMediaSource) return "View Image";
    if (mediaKind === "video" && hasMediaSource) return "Watch Video";
    if (mediaKind === "audio" && hasMediaSource) return "Play Audio";
    if (mediaKind === "document" && hasMediaSource) return "Open Document";
    if (mediaKind === "file" && hasMediaSource) return "Open File";
    if (hasMediaSource) return "Open Material";
    return fromApi ? "Open Material" : "Preview";
  }

  function resolveYoutubeUrl(value = "") {
    const normalized = String(value || "").trim();
    return /^https?:\/\//i.test(normalized) ? normalized : "";
  }

  function renderResources(resources, fromApi, gridElement = ui.resourceGrid) {
    if (!gridElement) return;

    gridElement.innerHTML = resources
      .map((item) => {
        const category = sanitize(item.category || "resource");
        const type = sanitize(item.type || "file");
        const title = sanitize(item.title || "Resource");
        const description = sanitize(item.description || "");
        const href = sanitize(item.link || "#");
        const mediaKind = getMediaKind(item);
        const hasMediaSource = href !== "#contact";
        const mediaPreview = renderMediaPreview(mediaKind, href, title);
        const youtubeUrl = sanitize(resolveYoutubeUrl(item.youtubeUrl || ""));
        const hasYoutubeUrl = Boolean(youtubeUrl);

        const isExternal = href.startsWith("http");
        const targetAttr = isExternal
          ? 'target="_blank" rel="noopener noreferrer"'
          : "";
        const linkLabel = resolveResourceLinkLabel(
          mediaKind,
          hasMediaSource,
          fromApi,
        );

        return `
          <article class="resource-card" data-reveal>
            <div class="resource-meta">
              <span>${category}</span>
              <span>${type}</span>
            </div>
            <h3>${title}</h3>
            <p>${description}</p>
            ${mediaPreview}
            <div class="resource-card-actions">
              <a
                class="resource-link"
                href="${href}"
                data-resource-title="${title}"
                data-resource-action="material"
                ${targetAttr}>
                ${linkLabel}
                <i class="fa-solid fa-arrow-right"></i>
              </a>
              ${
                hasYoutubeUrl
                  ? `
                    <a
                      class="resource-link resource-link-youtube"
                      href="${youtubeUrl}"
                      target="_blank"
                      rel="noopener noreferrer"
                      data-resource-title="${title}"
                      data-resource-action="youtube">
                      See Video
                      <i class="fa-brands fa-youtube"></i>
                    </a>
                  `
                  : ""
              }
            </div>
          </article>
        `;
      })
      .join("");

    setupRevealAnimations();
    gridElement.querySelectorAll(".resource-link").forEach((link) => {
      link.addEventListener("click", () => {
        trackEvent("resource_open", {
          title: link.dataset.resourceTitle || "resource",
          source: fromApi ? "api" : "fallback",
          action: link.dataset.resourceAction || "open",
        });
      });
    });
  }

  function setResourceNotice(text, tone = "") {
    if (!ui.resourceNotice) return;

    ui.resourceNotice.textContent = text;
    ui.resourceNotice.className = "resource-notice";

    if (tone === "warning") ui.resourceNotice.classList.add("is-warning");
    if (tone === "error") ui.resourceNotice.classList.add("is-error");
    if (tone === "success") ui.resourceNotice.classList.add("is-success");
  }

  function setupDailyPromise() {
    const hasDailyUpdate = Boolean(ui.dailyUpdatePromiseText);

    if (!hasDailyUpdate) return;

    ui.dailyUpdateToggleBtn?.addEventListener("click", () => {
      toggleDailyPromiseTextExpanded();
    });

    const applyDailyPromise = (promise, allPromises = []) => {
      if (!promise) {
        clearDailyPromise();
        return;
      }

      const promiseText = promise.promise_text || "No promise text.";
      const promiseAuthor = promise.author || "Scripture";
      const formattedDate = formatPromiseDate(
        promise.created_at || promise.updated_at || new Date().toISOString(),
      );

      if (ui.dailyUpdatePromiseText) {
        setDailyPromiseText(promiseText);
      }
      if (ui.dailyUpdatePromiseAuthor) {
        ui.dailyUpdatePromiseAuthor.textContent = promiseAuthor;
      }
      if (ui.dailyUpdatePromiseDate) {
        ui.dailyUpdatePromiseDate.textContent = `Posted on ${formattedDate}`;
      }

      renderDailyPromiseHistory(allPromises);
      setupDailyPromiseComments(promise);
    };

    const clearDailyPromise = () => {
      if (ui.dailyUpdatePromiseText) {
        setDailyPromiseText("No daily promise has been posted yet.");
      }
      if (ui.dailyUpdatePromiseAuthor) {
        ui.dailyUpdatePromiseAuthor.textContent = "";
      }
      if (ui.dailyUpdatePromiseDate) {
        ui.dailyUpdatePromiseDate.textContent = "";
      }
      renderDailyPromiseHistory([]);
      clearDailyPromiseComments();
    };

    const fetchJson = async (url) => {
      const response = await fetch(url);
      const data = await response
        .json()
        .catch(() => ({ error: "Unexpected response format." }));
      if (!response.ok) {
        throw new Error(data?.error || "Request failed");
      }
      return data;
    };

    const loadDailyPromises = async () => {
      try {
        const promiseLimit = ui.dailyPromiseHistoryList ? 100 : 4;
        const data = await fetchJson(
          `${API_BASE}/daily-promises?limit=${promiseLimit}`,
        );
        const promises = Array.isArray(data?.promises) ? data.promises : [];
        if (!promises.length) {
          clearDailyPromise();
          return;
        }
        applyDailyPromise(promises[0], promises);
      } catch (error) {
        try {
          const data = await fetchJson(`${API_BASE}/daily-promise/latest`);
          if (!data?.promise) {
            clearDailyPromise();
            return;
          }
          applyDailyPromise(data.promise, [data.promise]);
        } catch (fallbackError) {
          clearDailyPromise();
        }
      }
    };

    loadDailyPromises();
  }

  function setupDevotionPage() {
    if (!ui.devotionList || !ui.devotionNotice) return;
    loadDevotionPosts();
  }

  function setDevotionNotice(text, tone = "") {
    if (!ui.devotionNotice) return;
    ui.devotionNotice.textContent = text;
    ui.devotionNotice.className = "resource-notice";

    if (tone === "warning") ui.devotionNotice.classList.add("is-warning");
    if (tone === "error") ui.devotionNotice.classList.add("is-error");
    if (tone === "success") ui.devotionNotice.classList.add("is-success");
  }

  function getAuthToken() {
    return (
      state.token ||
      localStorage.getItem("authToken") ||
      localStorage.getItem("adminToken")
    );
  }

  function normalizeCommunityFilter(value = "") {
    const normalized = String(value || "")
      .trim()
      .toLowerCase();
    const allowedFilters = new Set(["all", "devotion", "promise", "reading"]);
    return allowedFilters.has(normalized) ? normalized : "all";
  }

  function buildCommunityUrl({ postType = "", postId = "", filter = "" } = {}) {
    const params = new URLSearchParams();
    const normalizedFilter = normalizeCommunityFilter(filter);
    const normalizedPostType = normalizeCommunityFilter(postType);
    const numericPostId = Number(postId);

    if (normalizedFilter !== "all") {
      params.set("filter", normalizedFilter);
    }

    if (normalizedPostType !== "all") {
      params.set("postType", normalizedPostType);
    }

    if (Number.isFinite(numericPostId) && numericPostId > 0) {
      params.set("postId", String(numericPostId));
    }

    const query = params.toString();
    return `${COMMUNITY_PAGE}${query ? `?${query}` : ""}#community-discussions`;
  }

  function getCommunityThreadElementId(postType, postId) {
    return `community-thread-${postType}-${postId}`;
  }

  function formatCommunityDate(value) {
    return new Date(value || Date.now()).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  }

  function getCommunityReadingThread() {
    return {
      id: COMMUNITY_READING_THREAD_ID,
      kind: "reading",
      author: "Bible Reading Circle",
      title: "Bible Reading Discussion Room",
      summary:
        "Share the verse that stood out to you, ask a question, or talk through the action step you are taking from today's reading.",
      href: "bible-reading.html",
      created_at: new Date().toISOString(),
      iconClass: "fa-book-bible",
      label: "Bible Reading",
      ctaLabel: "Open Bible Reading",
    };
  }

  function sortCommunityThreads(threads = []) {
    return [...threads].sort((left, right) => {
      if (left.kind === "reading" && right.kind !== "reading") return -1;
      if (right.kind === "reading" && left.kind !== "reading") return 1;
      return (
        new Date(right.created_at || Date.now()) -
        new Date(left.created_at || Date.now())
      );
    });
  }

  function renderCommunityThread(thread) {
    const postType = normalizeCommunityFilter(thread?.kind);
    const postId = Number(thread?.id);
    const title = sanitize(thread?.title || "Community Discussion");
    const author = sanitize(thread?.author || "Community");
    const label = sanitize(thread?.label || "Discussion");
    const href = sanitize(thread?.href || "#");
    const ctaLabel = sanitize(thread?.ctaLabel || "Open Source Page");
    const iconClass = sanitize(thread?.iconClass || "fa-comments");
    const summarySource = String(thread?.summary || "")
      .replace(/\s+/g, " ")
      .trim();
    const summary = sanitize(
      summarySource.length > 240
        ? `${summarySource.slice(0, 240)}...`
        : summarySource,
    );
    const date = formatCommunityDate(thread?.created_at);
    const isFocused =
      communityState.focusType === postType &&
      communityState.focusId === String(postId);

    return `
      <article
        class="feed-post-card community-thread-card${isFocused ? " is-focused" : ""}"
        id="${getCommunityThreadElementId(postType, postId)}"
        data-thread-type="${postType}"
        data-thread-id="${postId}"
        data-reveal>
        <div class="feed-post-header">
          <div class="feed-post-avatar"><i class="fa-solid ${iconClass}"></i></div>
          <div class="feed-post-meta">
            <strong>${author}</strong>
            <span class="feed-post-type">${label}</span>
            <span class="feed-post-date">${sanitize(date)}</span>
          </div>
        </div>
        <h3 class="feed-post-title">${title}</h3>
        <p class="feed-post-body">${summary}</p>
        <div class="feed-post-actions">
          <a href="${href}" class="feed-action-btn">
            <i class="fa-solid fa-arrow-up-right-from-square"></i> ${ctaLabel}
          </a>
        </div>
        <div class="feed-comments-box">
          <p class="community-thread-hint guest-only">
            Sign in to add your encouragement, questions, and prayer responses.
          </p>
          <div
            class="feed-comments-list"
            id="community-comments-list-${postType}-${postId}">
            <p style="color: var(--ink-soft); font-size: 0.85rem;">Loading comments...</p>
          </div>
          <form
            class="feed-comment-form community-comment-form"
            data-post-id="${postId}"
            data-post-type="${postType}">
            <input
              type="text"
              class="comment-input"
              placeholder="Write a response for the community..."
              required />
            <button
              type="submit"
              class="btn btn-solid"
              style="padding: 8px 14px; font-size: 0.82rem;">
              <i class="fa-solid fa-paper-plane"></i>
            </button>
          </form>
        </div>
      </article>
    `;
  }

  function syncCommunityFilterButtons() {
    ui.communityFilterButtons.forEach((button) => {
      const buttonFilter = normalizeCommunityFilter(
        button.dataset.communityFilter,
      );
      const isActive = buttonFilter === communityState.activeFilter;
      button.classList.toggle("active", isActive);
      button.setAttribute("aria-pressed", String(isActive));
    });
  }

  function focusCommunityThread() {
    if (!communityState.focusType || !communityState.focusId) return;

    const target = document.getElementById(
      getCommunityThreadElementId(
        communityState.focusType,
        communityState.focusId,
      ),
    );
    if (!target) return;

    requestAnimationFrame(() => {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function bindCommunityCommentForms() {
    document.querySelectorAll(".community-comment-form").forEach((form) => {
      if (form.dataset.bound === "true") return;
      form.dataset.bound = "true";

      form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const input = form.querySelector(".comment-input");
        const text = input?.value.trim();
        const postType = normalizeCommunityFilter(form.dataset.postType);
        const postId = form.dataset.postId;
        const token = getAuthToken();

        if (!text) return;

        if (!token) {
          notify("Please sign in to join the community discussion.", "error");
          return;
        }

        if (!postId || postType === "all") {
          notify(
            "Unable to open this discussion right now. Please refresh.",
            "error",
          );
          return;
        }

        try {
          const response = await fetch(`${API_BASE}/comments`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
              post_type: postType,
              post_id: postId,
              comment_text: text,
            }),
          });

          const data = await response
            .json()
            .catch(() => ({ error: "Unexpected response format." }));

          if (!response.ok) {
            throw new Error(data?.error || "Failed to send response.");
          }

          if (input) {
            input.value = "";
          }

          const listElement = document.getElementById(
            `community-comments-list-${postType}-${postId}`,
          );
          await loadCommentsForPost(postType, postId, listElement);
        } catch (error) {
          notify("Unable to send your response. Please try again.", "error");
        }
      });
    });
  }

  function renderCommunityThreads() {
    if (!ui.communityThreads || !ui.communityNotice) return;

    const visibleThreads = communityState.threads.filter((thread) => {
      if (communityState.activeFilter === "all") return true;
      return (
        normalizeCommunityFilter(thread?.kind) === communityState.activeFilter
      );
    });

    syncCommunityFilterButtons();

    if (!visibleThreads.length) {
      ui.communityNotice.textContent =
        "No discussion threads are available for this view yet.";
      ui.communityNotice.className = "resource-notice is-warning";
      ui.communityThreads.innerHTML = "";
      return;
    }

    ui.communityNotice.textContent =
      communityState.activeFilter === "all"
        ? "Discuss the latest devotion, promise, and Bible reading posts with the ministry community."
        : `Showing ${communityState.activeFilter} discussions.`;
    ui.communityNotice.className = "resource-notice";
    ui.communityThreads.innerHTML = visibleThreads
      .map(renderCommunityThread)
      .join("");

    visibleThreads.forEach((thread) => {
      const listElement = document.getElementById(
        `community-comments-list-${thread.kind}-${thread.id}`,
      );
      if (listElement) {
        loadCommentsForPost(thread.kind, thread.id, listElement);
      }
    });

    bindCommunityCommentForms();
    setupRevealAnimations();
    focusCommunityThread();
  }

  async function loadCommunityThreads() {
    if (!ui.communityThreads || !ui.communityNotice) return;

    ui.communityNotice.textContent = "Loading community discussions...";
    ui.communityNotice.className = "resource-notice";

    const [devotionData, promiseData] = await Promise.all([
      fetch(`${API_BASE}/devotion-posts?limit=12`)
        .then((response) => (response.ok ? response.json() : null))
        .catch(() => null),
      fetch(`${API_BASE}/daily-promises?limit=12`)
        .then((response) => (response.ok ? response.json() : null))
        .catch(() => null),
    ]);

    const devotionThreads = Array.isArray(devotionData?.posts)
      ? devotionData.posts.map((post) => ({
          id: Number(post.id),
          kind: "devotion",
          author: post.author || "Pst. Wisdom C. Adiele",
          title: post.title || "Daily Devotion",
          summary: post.devotion_text || "",
          href: "devotion.html",
          created_at:
            post.created_at || post.updated_at || new Date().toISOString(),
          iconClass: "fa-fire-flame-curved",
          label: "Devotion",
          ctaLabel: "Open Devotion Page",
        }))
      : [];

    const promiseThreads = Array.isArray(promiseData?.promises)
      ? promiseData.promises.map((post) => ({
          id: Number(post.id),
          kind: "promise",
          author: post.author || "Scripture",
          title: post.title || "Daily Promise",
          summary: post.promise_text || "",
          href: "daily-promise.html",
          created_at:
            post.created_at || post.updated_at || new Date().toISOString(),
          iconClass: "fa-star",
          label: "Daily Promise",
          ctaLabel: "Open Promise Page",
        }))
      : [];

    communityState.threads = sortCommunityThreads([
      getCommunityReadingThread(),
      ...devotionThreads.filter((thread) => Number.isFinite(thread.id)),
      ...promiseThreads.filter((thread) => Number.isFinite(thread.id)),
    ]);

    renderCommunityThreads();
  }

  function setupCommunityPage() {
    if (!ui.communityThreads || !ui.communityNotice) return;

    const params = new URLSearchParams(window.location.search);
    const requestedFilter =
      params.get("filter") || params.get("postType") || "all";
    const requestedPostType = params.get("postType") || "";
    const requestedPostId = Number(params.get("postId"));

    communityState.activeFilter = normalizeCommunityFilter(requestedFilter);
    communityState.focusType = normalizeCommunityFilter(requestedPostType);
    communityState.focusId =
      Number.isFinite(requestedPostId) && requestedPostId > 0
        ? String(requestedPostId)
        : "";

    ui.communityFilterButtons.forEach((button) => {
      if (button.dataset.bound === "true") return;
      button.dataset.bound = "true";

      button.addEventListener("click", () => {
        communityState.activeFilter = normalizeCommunityFilter(
          button.dataset.communityFilter,
        );
        renderCommunityThreads();
      });
    });

    syncCommunityFilterButtons();
    loadCommunityThreads().catch(() => {
      ui.communityNotice.textContent =
        "Unable to load the community right now. Please try again soon.";
      ui.communityNotice.className = "resource-notice is-warning";
      ui.communityThreads.innerHTML = "";
    });
  }

  function renderDevotionPost(post) {
    const title = sanitize(post?.title || "Daily Devotion");
    const author = sanitize(post?.author || "Pst. Wisdom C. Adiele");
    const text = sanitize(post?.devotion_text || "");
    const date = new Date(post?.created_at || Date.now()).toLocaleDateString(
      undefined,
      {
        year: "numeric",
        month: "long",
        day: "numeric",
      },
    );
    const formattedText = text.replace(/\n/g, "<br />");

    return `
      <article class="devotion-card" data-reveal>
        <div class="devotion-meta">
          <span>${author}</span>
          <span>${date}</span>
        </div>
        <h3>${title}</h3>
        <p>${formattedText}</p>
        <div class="feed-post-actions">
          <a
            href="${buildCommunityUrl({ postType: "devotion", postId: post?.id, filter: "devotion" })}"
            class="feed-action-btn">
            <i class="fa-solid fa-users"></i> Open Community
          </a>
        </div>
        <div class="feed-comments-box">
          <div class="feed-comments-list" id="devotion-comments-list-${post.id}">
            <p style="color: var(--ink-soft); font-size: 0.85rem;">Loading comments...</p>
          </div>
          <form class="feed-comment-form devotion-comment-form" data-post-id="${post.id}">
            <input
              type="text"
              class="comment-input"
              placeholder="Share a comment..."
              required />
            <button
              type="submit"
              class="btn btn-solid"
              style="padding: 8px 14px; font-size: 0.82rem;">
              <i class="fa-solid fa-paper-plane"></i>
            </button>
          </form>
        </div>
      </article>
    `;
  }

  async function loadDevotionPosts() {
    setDevotionNotice("Loading devotion posts...");

    try {
      const response = await fetch(`${API_BASE}/devotion-posts?limit=12`);
      const data = await response
        .json()
        .catch(() => ({ error: "Unexpected response format." }));

      if (response.status === 404) {
        setDevotionNotice(
          "No devotion posts yet. Please check back soon!",
          "warning",
        );
        ui.devotionList.innerHTML = "";
        return;
      }

      if (!response.ok) {
        throw new Error(data?.error || "Failed to load devotion posts.");
      }

      const posts = Array.isArray(data?.posts) ? data.posts : [];
      if (!posts.length) {
        setDevotionNotice(
          "No devotion posts yet. Please check back soon!",
          "warning",
        );
        ui.devotionList.innerHTML = "";
        return;
      }

      setDevotionNotice("", "");
      ui.devotionList.innerHTML = posts.map(renderDevotionPost).join("");
      bindDevotionComments(posts);
      setupRevealAnimations();
    } catch (error) {
      setDevotionNotice(
        "Unable to load devotion posts at the moment. Please try again soon.",
        "error",
      );
    }
  }

  function bindDevotionComments(posts = []) {
    posts.forEach((post) => {
      const listElement = document.getElementById(
        `devotion-comments-list-${post.id}`,
      );
      if (listElement) {
        loadCommentsForPost("devotion", post.id, listElement);
      }
    });

    document.querySelectorAll(".devotion-comment-form").forEach((form) => {
      if (form.dataset.bound === "true") return;
      form.dataset.bound = "true";

      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const input = form.querySelector(".comment-input");
        const text = input?.value.trim();
        if (!text) return;

        const token =
          state.token ||
          localStorage.getItem("authToken") ||
          localStorage.getItem("adminToken");
        if (!token) {
          notify("Please sign in to comment.", "error");
          return;
        }

        const postId = form.dataset.postId;
        if (!postId) {
          notify("Unable to comment right now. Please refresh.", "error");
          return;
        }

        try {
          await fetch(`${API_BASE}/comments`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
              post_type: "devotion",
              post_id: postId,
              comment_text: text,
            }),
          });

          if (input) {
            input.value = "";
          }

          const listElement = document.getElementById(
            `devotion-comments-list-${postId}`,
          );
          await loadCommentsForPost("devotion", postId, listElement);
        } catch (error) {
          notify("Unable to send comment. Please try again.", "error");
        }
      });
    });
  }

  function renderDailyPromiseHistory(promises = []) {
    if (!ui.dailyPromiseHistory || !ui.dailyPromiseHistoryList) return;

    const historyItems = Array.isArray(promises) ? promises.slice(1) : [];
    ui.dailyPromiseHistoryList.innerHTML = "";

    if (!historyItems.length) {
      ui.dailyPromiseHistory.hidden = true;
      return;
    }

    historyItems.forEach((promise) => {
      const item = document.createElement("article");
      item.className = "daily-promise-history-item";

      const text = document.createElement("p");
      text.className = "daily-promise-history-text";
      text.textContent = promise?.promise_text || "";

      const meta = document.createElement("p");
      meta.className = "daily-promise-history-meta";
      const author = promise?.author || "Scripture";
      const date = formatPromiseDate(
        promise?.created_at || promise?.updated_at || new Date().toISOString(),
      );
      meta.textContent = `${author} - ${date}`;

      const actions = document.createElement("div");
      actions.className = "feed-post-actions";
      actions.innerHTML = `
        <a
          href="${buildCommunityUrl({ postType: "promise", postId: promise?.id, filter: "promise" })}"
          class="feed-action-btn">
          <i class="fa-solid fa-users"></i> Open Community
        </a>
      `;

      item.append(text, meta, actions);

      if (promise?.id) {
        const commentsBox = document.createElement("div");
        commentsBox.className = "feed-comments-box";

        const commentsList = document.createElement("div");
        commentsList.className = "feed-comments-list";
        commentsList.id = `promise-comments-list-${promise.id}`;
        commentsList.innerHTML =
          '<p style="color: var(--ink-soft); font-size: 0.85rem;">Loading comments...</p>';

        const commentForm = document.createElement("form");
        commentForm.className = "feed-comment-form promise-comment-form";
        commentForm.dataset.postId = String(promise.id);
        commentForm.innerHTML = `
          <input
            type="text"
            class="comment-input"
            placeholder="Write a comment..."
            required />
          <button
            type="submit"
            class="btn btn-solid"
            style="padding: 8px 14px; font-size: 0.82rem;">
            <i class="fa-solid fa-paper-plane"></i>
          </button>
        `;

        commentsBox.append(commentsList, commentForm);
        item.append(commentsBox);
      }

      ui.dailyPromiseHistoryList.appendChild(item);
    });

    ui.dailyPromiseHistory.hidden = false;
    bindPromiseHistoryComments(historyItems);
  }

  function clearDailyPromiseComments() {
    if (!ui.dailyPromiseCommentsList) return;
    ui.dailyPromiseCommentsList.innerHTML =
      '<p style="color: var(--ink-soft); font-size: 0.85rem;">No promise selected.</p>';
    if (ui.dailyPromiseCommentForm) {
      ui.dailyPromiseCommentForm.dataset.postId = "";
    }
  }

  function bindPromiseHistoryComments(promises = []) {
    promises.forEach((promise) => {
      const listElement = document.getElementById(
        `promise-comments-list-${promise.id}`,
      );
      if (listElement) {
        loadCommentsForPost("promise", promise.id, listElement);
      }
    });

    document.querySelectorAll(".promise-comment-form").forEach((form) => {
      if (form.dataset.bound === "true") return;
      form.dataset.bound = "true";

      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const input = form.querySelector(".comment-input");
        const text = input?.value.trim();
        if (!text) return;

        const token =
          state.token ||
          localStorage.getItem("authToken") ||
          localStorage.getItem("adminToken");
        if (!token) {
          notify("Please sign in to comment.", "error");
          return;
        }

        const postId = form.dataset.postId;
        if (!postId) {
          notify("Unable to comment right now. Please refresh.", "error");
          return;
        }

        try {
          await fetch(`${API_BASE}/comments`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
              post_type: "promise",
              post_id: postId,
              comment_text: text,
            }),
          });

          if (input) {
            input.value = "";
          }

          const listElement = document.getElementById(
            `promise-comments-list-${postId}`,
          );
          await loadCommentsForPost("promise", postId, listElement);
        } catch (error) {
          notify("Unable to send comment. Please try again.", "error");
        }
      });
    });
  }

  function renderCommentItem(comment) {
    const username = sanitize(comment?.username || "Member");
    const initial = username.charAt(0).toUpperCase();
    const text = sanitize(comment?.comment_text || "");
    const date = new Date(
      comment?.created_at || Date.now(),
    ).toLocaleDateString();

    return `
      <div class="feed-comment">
        <div class="comment-avatar">${initial}</div>
        <div class="comment-body">
          <strong>${username}</strong>
          <p>${text}</p>
          <span class="comment-date">${date}</span>
        </div>
      </div>
    `;
  }

  async function loadCommentsForPost(postType, postId, listElement) {
    if (!listElement || !postType || !postId) return;
    listElement.innerHTML =
      '<p style="color: var(--ink-soft); font-size: 0.85rem;">Loading comments...</p>';

    try {
      const response = await fetch(
        `${API_BASE}/comments?post_type=${postType}&post_id=${postId}`,
      );
      const data = await response
        .json()
        .catch(() => ({ error: "Unexpected response format." }));

      if (!response.ok) {
        throw new Error(data?.error || "Failed to load comments.");
      }

      const comments = Array.isArray(data?.comments) ? data.comments : [];
      if (!comments.length) {
        listElement.innerHTML =
          '<p style="color: var(--ink-soft); font-size: 0.85rem;">No comments yet. Be the first!</p>';
        return;
      }

      listElement.innerHTML = comments.map(renderCommentItem).join("");
    } catch (error) {
      listElement.innerHTML =
        '<p style="color: var(--ink-soft); font-size: 0.85rem;">Unable to load comments.</p>';
    }
  }

  function setupDailyPromiseComments(promise) {
    if (
      !ui.dailyPromiseCommentsList ||
      !ui.dailyPromiseCommentForm ||
      !ui.dailyPromiseCommentInput
    ) {
      return;
    }

    const postId = promise?.id;
    if (!postId) {
      clearDailyPromiseComments();
      if (ui.dailyPromiseCommunityLink) {
        ui.dailyPromiseCommunityLink.href = buildCommunityUrl({
          filter: "promise",
        });
      }
      return;
    }

    ui.dailyPromiseCommentForm.dataset.postId = String(postId);
    if (ui.dailyPromiseCommunityLink) {
      ui.dailyPromiseCommunityLink.href = buildCommunityUrl({
        postType: "promise",
        postId,
        filter: "promise",
      });
    }
    loadCommentsForPost("promise", postId, ui.dailyPromiseCommentsList);

    if (ui.dailyPromiseCommentForm.dataset.bound === "true") {
      return;
    }

    ui.dailyPromiseCommentForm.dataset.bound = "true";
    ui.dailyPromiseCommentForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const text = ui.dailyPromiseCommentInput.value.trim();
      if (!text) return;

      const token =
        state.token ||
        localStorage.getItem("authToken") ||
        localStorage.getItem("adminToken");
      if (!token) {
        notify("Please sign in to comment.", "error");
        return;
      }

      const formPostId = ui.dailyPromiseCommentForm.dataset.postId;
      if (!formPostId) {
        notify("Unable to comment right now. Please refresh.", "error");
        return;
      }

      try {
        await fetch(`${API_BASE}/comments`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            post_type: "promise",
            post_id: formPostId,
            comment_text: text,
          }),
        });

        ui.dailyPromiseCommentInput.value = "";
        await loadCommentsForPost(
          "promise",
          formPostId,
          ui.dailyPromiseCommentsList,
        );
      } catch (error) {
        notify("Unable to send comment. Please try again.", "error");
      }
    });
  }

  function setDailyPromiseText(rawText = "") {
    if (!ui.dailyUpdatePromiseText) return;

    const normalizedText =
      String(rawText).trim() || "No daily promise has been posted yet.";
    const shouldCollapse =
      normalizedText.length > DAILY_PROMISE_COLLAPSE_MIN_CHARS;

    ui.dailyUpdatePromiseText.textContent = normalizedText;
    ui.dailyUpdatePromiseText.classList.toggle("is-collapsed", shouldCollapse);

    if (ui.dailyUpdateToggleBtn) {
      ui.dailyUpdateToggleBtn.hidden = !shouldCollapse;
      ui.dailyUpdateToggleBtn.textContent = "View More";
      ui.dailyUpdateToggleBtn.setAttribute("aria-expanded", "false");
    }
  }

  function toggleDailyPromiseTextExpanded() {
    if (!ui.dailyUpdatePromiseText || !ui.dailyUpdateToggleBtn) return;
    if (ui.dailyUpdateToggleBtn.hidden) return;

    const isExpanded =
      ui.dailyUpdateToggleBtn.getAttribute("aria-expanded") === "true";
    const nextExpanded = !isExpanded;

    ui.dailyUpdatePromiseText.classList.toggle("is-collapsed", !nextExpanded);
    ui.dailyUpdateToggleBtn.textContent = nextExpanded
      ? "View Less"
      : "View More";
    ui.dailyUpdateToggleBtn.setAttribute("aria-expanded", String(nextExpanded));

    trackEvent("daily_promise_expand_toggle", {
      source: "daily_update",
      state: nextExpanded ? "expanded" : "collapsed",
    });
  }

  function formatPromiseDate(rawDate) {
    const date = new Date(rawDate);
    if (Number.isNaN(date.getTime())) return "today";
    return date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  }

  function openWhatsApp(message, source = "direct") {
    const text = encodeURIComponent(message);
    trackEvent("whatsapp_open", { source });
    window.open(`https://wa.me/${WHATSAPP_PHONE}?text=${text}`, "_blank");
  }

  function setupGoogleMap() {
    if (!ui.googleMapEmbed && !ui.googleDirectionsLink) return;

    const buildMapUrls = (query) => {
      const encodedQuery = encodeURIComponent(
        String(query || DEFAULT_MAP_QUERY),
      );
      return {
        embedUrl: `https://www.google.com/maps?q=${encodedQuery}&output=embed`,
        directionsUrl: `https://www.google.com/maps/search/?api=1&query=${encodedQuery}`,
      };
    };

    const setMapTargets = (embedUrl, directionsUrl) => {
      if (ui.googleMapEmbed) {
        ui.googleMapEmbed.src = embedUrl;
      }

      if (ui.googleDirectionsLink) {
        ui.googleDirectionsLink.href = directionsUrl;
      }
    };

    const configuredEmbedUrl = GOOGLE_MAPS_EMBED_URL || "";
    const configuredDirectionsUrl = GOOGLE_MAPS_DIRECTIONS_URL || "";
    const fallbackUrls = buildMapUrls(DEFAULT_MAP_QUERY);

    setMapTargets(
      configuredEmbedUrl || fallbackUrls.embedUrl,
      configuredDirectionsUrl || fallbackUrls.directionsUrl,
    );

    if (ui.googleDirectionsLink) {
      ui.googleDirectionsLink.addEventListener("click", () => {
        trackEvent("google_maps_open", { source: "contact_section" });
      });
    }

    if (!navigator.geolocation) {
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        const latitude = Number(position?.coords?.latitude);
        const longitude = Number(position?.coords?.longitude);
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
          return;
        }

        const locationQuery = `Seventh-day Adventist church near ${latitude.toFixed(5)},${longitude.toFixed(5)}`;
        const localizedUrls = buildMapUrls(locationQuery);
        setMapTargets(localizedUrls.embedUrl, localizedUrls.directionsUrl);
        trackEvent("google_maps_localized", { source: "geolocation" });
      },
      () => {
        trackEvent("google_maps_localized", { source: "fallback" });
      },
      {
        enableHighAccuracy: false,
        timeout: 9000,
        maximumAge: 30 * 60 * 1000,
      },
    );
  }

  function setupGoogleAnalytics() {
    if (!GOOGLE_ANALYTICS_ID) return;

    if (typeof window.gtag === "function") {
      window.gtag("config", GOOGLE_ANALYTICS_ID, { anonymize_ip: true });
      return;
    }

    const tagScript = document.createElement("script");
    tagScript.async = true;
    tagScript.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(GOOGLE_ANALYTICS_ID)}`;
    document.head.appendChild(tagScript);

    window.dataLayer = window.dataLayer || [];
    window.gtag = function gtag() {
      window.dataLayer.push(arguments);
    };

    window.gtag("js", new Date());
    window.gtag("config", GOOGLE_ANALYTICS_ID, {
      anonymize_ip: true,
      transport_type: "beacon",
    });
  }

  function trackEvent(eventName, params = {}) {
    if (typeof window.gtag !== "function") return;
    window.gtag("event", eventName, params);
  }

  function sanitize(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function notify(message, tone = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${tone}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    requestAnimationFrame(() => {
      toast.classList.add("show");
    });

    setTimeout(() => {
      toast.classList.remove("show");
      setTimeout(() => toast.remove(), 220);
    }, 2600);
  }

  return { init };
})();

window.addEventListener("DOMContentLoaded", App.init);
