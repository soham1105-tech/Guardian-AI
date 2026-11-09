import { createContext, useContext, useEffect, useState } from "react";

const ThemeContext = createContext();

// Dark is the DEFAULT. Light mode is only an option behind the toggle.
export const THEMES = {
  dark: { label: "Dark", icon: "moon" },
  light: { label: "Light", icon: "sun" },
};

const LEGACY_THEME_MAP = { cyberpunk: "dark", dim: "dark" };

function readStoredTheme() {
  const legacyKey = ["phish", "guard-theme"].join("");
  const stored = localStorage.getItem("guardian-theme") || localStorage.getItem(legacyKey);
  if (!stored) return "dark";
  const migrated = LEGACY_THEME_MAP[stored] || stored;
  return THEMES[migrated] ? migrated : "dark";
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(readStoredTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("guardian-theme", theme);
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
