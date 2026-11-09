// ThemeToggle.jsx — appearance switch (dark default, light behind toggle).
import { useTheme, THEMES } from "../context/ThemeContext";
import Icon from "./Icon";

function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div
      className="flex items-center"
      style={{
        gap: 2,
        padding: 2,
        borderRadius: 10,
        border: "1px solid var(--border)",
        background: "var(--bg-secondary)",
      }}
      role="group"
      aria-label="Appearance"
    >
      {Object.entries(THEMES).map(([key, { label, icon }]) => {
        const isActive = theme === key;
        return (
          <button
            key={key}
            type="button"
            onClick={() => setTheme(key)}
            aria-pressed={isActive}
            title={`${label} appearance`}
            style={{
              display: "grid",
              placeItems: "center",
              width: 32,
              height: 32,
              borderRadius: 8,
              border: "none",
              cursor: "pointer",
              background: isActive ? "var(--accent-soft)" : "transparent",
              color: isActive ? "var(--accent)" : "var(--text-muted)",
              transition: "background-color 0.15s ease-out, color 0.15s ease-out",
            }}
          >
            <Icon name={icon} size={15} />
            <span className="sr-only">{label}</span>
          </button>
        );
      })}
    </div>
  );
}

export default ThemeToggle;
