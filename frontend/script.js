document.documentElement.classList.add("js");

const App = (() => {
  const WHATSAPP_PHONE = "2349072560420";
  const CONTACT_EMAIL = "Wisdomadiele57@gmail.com";
  const DEFAULT_MAP_QUERY = "Seventh-day Adventist church near me";

  const getConfigString = (key) => {
    const value = window.APP_CONFIG?.[key] ?? window.__APP_CONFIG__?.[key];
    return typeof value === "string" ? value.trim() : "";
  };

  const GOOGLE_ANALYTICS_ID = getConfigString("GOOGLE_ANALYTICS_ID");
  const GOOGLE_MAPS_EMBED_URL = getConfigString("GOOGLE_MAPS_EMBED_URL");
  const GOOGLE_MAPS_DIRECTIONS_URL = getConfigString("GOOGLE_MAPS_DIRECTIONS_URL");

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
    configuredApiBase ||
      (isLocalHost ? "http://localhost:5501" : window.location.origin),
  );
  const BACKEND_ORIGIN = API_BASE.replace(/\/api\/?$/, "");
  const POST_AUTH_REDIRECT_KEY = "postAuthRedirect";
  const DAILY_PROMISE_COLLAPSE_MIN_CHARS = 260;
  const RESOURCE_PAGE_SIZE = 6;
  const RESOURCE_MAX_LIMIT = 100;
  const ALL_MATERIALS_PAGE_SIZE = 24;

  const state = {
    token: localStorage.getItem("authToken") || localStorage.getItem("adminToken"),
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

  const ui = {
    header: document.getElementById("siteHeader"),
    navToggle: document.getElementById("navToggle"),
    mainNav: document.getElementById("mainNav"),
    navOverlay: document.getElementById("navOverlay"),
    navDropdownTrigger: document.getElementById("exploreDropdownBtn"),
    navDropdownMenu: document.getElementById("exploreDropdownMenu"),
    openAuthBtns: Array.from(document.querySelectorAll("[data-open-auth]")),
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
    googleMapEmbed: document.getElementById("googleMapEmbed"),
    googleDirectionsLink: document.getElementById("googleDirectionsLink"),
    year: document.getElementById("year"),
    // Prayer Page
    prayerPageForm: document.getElementById("prayerForm"),
    prayerPageName: document.getElementById("prayerName"),
    prayerPageEmail: document.getElementById("prayerEmail"),
    prayerPageRequest: document.getElementById("prayerRequest"),
    prayerPageAnonymous: document.getElementById("prayerAnonymous"),
    prayerFormContainer: document.getElementById("prayer-form-container"),
    prayerBookingForm: document.getElementById("prayerBookingForm"),
    prayerBookingName: document.getElementById("prayerBookingName"),
    prayerBookingEmail: document.getElementById("prayerBookingEmail"),
    prayerBookingAvailability: document.getElementById("prayerBookingAvailability"),
    prayerBookingFocus: document.getElementById("prayerBookingFocus"),
    // Counseling Page
    counselingPageForm: document.getElementById("counselingForm"),
    counselingIntent: document.getElementById("counselingIntent"),
    counselingType: document.getElementById("counselingType"),
    counselingDescription: document.getElementById("counselingDescription"),
    counselingAvailability: document.getElementById("counselingAvailability"),
    counselingFormContainer: document.getElementById("counseling-form-container"),
    // General
    loginWall: document.getElementById("login-wall"),
    loginBtn: document.getElementById("login-btn"),
    formMessage: document.getElementById("form-message"),
    // Daily Promise
    dailyUpdatePromiseText: document.getElementById("dailyUpdatePromiseText"),
    dailyUpdateToggleBtn: document.getElementById("dailyUpdateToggleBtn"),
    dailyUpdatePromiseAuthor: document.getElementById("dailyUpdatePromiseAuthor"),
    dailyUpdatePromiseDate: document.getElementById("dailyUpdatePromiseDate"),
    dailyPromiseHistory: document.getElementById("dailyPromiseHistory"),
    dailyPromiseHistoryList: document.getElementById("dailyPromiseHistoryList"),
    dailyPromiseCommentsList: document.getElementById("dailyPromiseCommentsList"),
    dailyPromiseCommentForm: document.getElementById("dailyPromiseCommentForm"),
    dailyPromiseCommentInput: document.getElementById("dailyPromiseCommentInput"),
    devotionList: document.getElementById("devotionList"),
    devotionNotice: document.getElementById("devotionNotice"),
  };

  function init() {
    setupGoogleAnalytics();
    setupGoogleMap();
    setYear();
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

    const syncMenuState = (isOpen) => {
      ui.mainNav.classList.toggle("open", isOpen);
      ui.navToggle.setAttribute("aria-expanded", String(isOpen));
      ui.navOverlay?.classList.toggle("open", isOpen);
      document.body.classList.toggle("nav-open", isOpen);
    };

    const closeMenu = () => {
      syncMenuState(false);
      ui.navDropdownMenu?.classList.remove("open");
      ui.navDropdownTrigger?.setAttribute("aria-expanded", "false");
    };

    ui.navToggle.setAttribute("aria-expanded", "false");
    ui.navToggle.setAttribute("aria-controls", "mainNav");

    ui.navToggle.addEventListener("click", () => {
      syncMenuState(!ui.mainNav.classList.contains("open"));
    });

    ui.mainNav.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        closeMenu();
        trackEvent("nav_click", { label: link.textContent?.trim() || "navigation" });
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
      if (window.innerWidth > 900) {
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

          const found = sectionMap.find((item) => item.section === entry.target);
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
    if (!ui.authModal) return;

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

    ui.openAuthBtns.forEach((button) => {
      button.addEventListener("click", () => {
        open(button.dataset.openAuthMode || "login");
      });
    });
    ui.resourceLoginBtn?.addEventListener("click", () => {
      open("login");
    });
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

    ui.logoutBtn?.addEventListener("click", () => {
      clearSession();
      updateAuthUI();
      loadResources();
      notify("You have been logged out.", "success");
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

      const body = [
        `Name: ${name}`,
        `Email: ${email}`,
        "",
        message,
      ].join("\n");

      const mailtoUrl = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
      window.location.href = mailtoUrl;
      trackEvent("contact_email_prepare", { subject });

      ui.contactForm.reset();
      notify("Opening your email app to send this message.", "success");
    });
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

        if (!response.ok || !data?.token) {
          throw new Error(data?.error || "Unable to create account.");
        }

        state.token = data.token;
        state.user = data.user || null;
        localStorage.setItem("authToken", data.token);

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
        setAuthMessage("Enter your account email before requesting a code.", true);
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
          setAuthMessage(data?.message || "Recovery instructions have been sent.", false);
        }
      } catch (error) {
        setAuthMessage(error.message || "Failed to request recovery code.", true);
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
        setAuthMessage("New password must be at least 8 characters long.", true);
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
      if (ui.prayerFormContainer) ui.prayerFormContainer.style.display = "block";
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
      const request = ui.prayerPageRequest?.value.trim();
      const is_anonymous = ui.prayerPageAnonymous?.checked;

      if (!request) {
        notify("Please enter your prayer request.", "error");
        return;
      }

      try {
        const response = await fetch(`${API_BASE}/prayer-requests`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${state.token}`,
          },
          body: JSON.stringify({ name, email, request, is_anonymous }),
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
      const availability = ui.prayerBookingAvailability?.value.trim();
      const focus = ui.prayerBookingFocus?.value.trim();

      if (!availability || !focus) {
        notify("Please complete booking availability and focus.", "error");
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
        setSectionMessage("Your prayer session booking has been sent.", "success");
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
      if (ui.counselingFormContainer) ui.counselingFormContainer.style.display = "block";
    };

    const setBlockedView = () => {
      if (ui.loginWall) ui.loginWall.style.display = "block";
      if (ui.counselingFormContainer) ui.counselingFormContainer.style.display = "none";
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
      const description = ui.counselingDescription?.value.trim();
      const preferred_availability = ui.counselingAvailability?.value.trim();

      if (!intent || !counseling_type || !description) {
        notify("Please select request option, type, and description.", "error");
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
            description: descriptionPayload,
            preferred_availability,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.error || "Unable to submit counseling request.");
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
  }

  function updateAuthUI() {
    const loggedIn = Boolean(state.token && state.user);

    if (ui.userBadge) {
      ui.userBadge.hidden = !loggedIn;
    }

    if (ui.logoutBtn) {
      ui.logoutBtn.hidden = !loggedIn;
    }

    if (ui.resourceLoginBtn) {
      ui.resourceLoginBtn.hidden = loggedIn;
    }

    ui.openAuthBtns.forEach((button) => {
      button.hidden = loggedIn;
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
        throw new Error(data?.error || "Failed to load resources.");
      }
      if (!data || data.success !== true) {
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
    const displayed = Math.min(resourceState.displayed, resourceState.items.length);
    renderResources(resourceState.items.slice(0, displayed), resourceState.fromApi);

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
        allMaterialsState.search || allMaterialsState.category || allMaterialsState.type
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
        return renderPreviewPlaceholder("fa-solid fa-headphones", "Audio Preview");
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
      return renderPreviewPlaceholder("fa-regular fa-file-lines", "Document Preview");
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

        const isExternal = href.startsWith("http");
        const targetAttr = isExternal ? 'target="_blank" rel="noopener noreferrer"' : "";
        const linkLabel = resolveResourceLinkLabel(mediaKind, hasMediaSource, fromApi);

        return `
          <article class="resource-card" data-reveal>
            <div class="resource-meta">
              <span>${category}</span>
              <span>${type}</span>
            </div>
            <h3>${title}</h3>
            <p>${description}</p>
            ${mediaPreview}
            <a class="resource-link" href="${href}" data-resource-title="${title}" ${targetAttr}>
              ${linkLabel}
              <i class="fa-solid fa-arrow-right"></i>
            </a>
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
        setDevotionNotice("No devotion posts yet. Please check back soon!", "warning");
        ui.devotionList.innerHTML = "";
        return;
      }

      if (!response.ok) {
        throw new Error(data?.error || "Failed to load devotion posts.");
      }

      const posts = Array.isArray(data?.posts) ? data.posts : [];
      if (!posts.length) {
        setDevotionNotice("No devotion posts yet. Please check back soon!", "warning");
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

      item.append(text, meta);

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
    const date = new Date(comment?.created_at || Date.now()).toLocaleDateString();

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
      return;
    }

    ui.dailyPromiseCommentForm.dataset.postId = String(postId);
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
        await loadCommentsForPost("promise", formPostId, ui.dailyPromiseCommentsList);
      } catch (error) {
        notify("Unable to send comment. Please try again.", "error");
      }
    });
  }

  function setDailyPromiseText(rawText = "") {
    if (!ui.dailyUpdatePromiseText) return;

    const normalizedText = String(rawText).trim() || "No daily promise has been posted yet.";
    const shouldCollapse = normalizedText.length > DAILY_PROMISE_COLLAPSE_MIN_CHARS;

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

    const isExpanded = ui.dailyUpdateToggleBtn.getAttribute("aria-expanded") === "true";
    const nextExpanded = !isExpanded;

    ui.dailyUpdatePromiseText.classList.toggle("is-collapsed", !nextExpanded);
    ui.dailyUpdateToggleBtn.textContent = nextExpanded ? "View Less" : "View More";
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
      const encodedQuery = encodeURIComponent(String(query || DEFAULT_MAP_QUERY));
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
