import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AttackDetector {

    private static final Map<String, List<Instant>> loginFailures = new ConcurrentHashMap<>();
    private static final Map<String, List<Instant>> commandFrequency = new ConcurrentHashMap<>();
    private static final Map<String, List<Double>> powerReadings = new ConcurrentHashMap<>();
    private static final List<String> alertLog = new ArrayList<>();

    public static void instrument(
            String eventName,
            String userRole,
            String userId,
            String sourceId,
            Instant timestamp,
            Map<String, Object> context) {

        switch (eventName) {
            case "login_attempt":
                detectFailedLogin(sourceId, timestamp, context);
                break;
            case "toggle_device":
                detectCommandSpam(sourceId, timestamp, userRole);
                break;
            case "power_reading":
                detectAbnormalPower(sourceId, context);
                break;
            case "temperature_change":
                detectSuspiciousTempControl(sourceId, timestamp);
                break;
            case "unauthorized_access":
                detectUnauthorizedAccess(userId, userRole, context);
                break;
            default:
                logEvent("Normal event: " + eventName);
        }
    }

    private static void detectFailedLogin(String sourceId, Instant timestamp, Map<String, Object> context) {
        boolean success = (boolean) context.getOrDefault("success", true);
        if (!success) {
            loginFailures.putIfAbsent(sourceId, new ArrayList<>());
            List<Instant> attempts = loginFailures.get(sourceId);
            attempts.add(timestamp);
            attempts.removeIf(t -> Duration.between(t, timestamp).toSeconds() > 60);
            if (attempts.size() > 5) {
                logAlert("ALERT: Too many failed login attempts from: " + sourceId);
            }
        }
    }

    private static void detectCommandSpam(String sourceId, Instant timestamp, String userRole) {
        if (userRole.equals("ADMIN") || userRole.equals("MANAGER")) return; // skip privileged users
        commandFrequency.putIfAbsent(sourceId, new ArrayList<>());
        List<Instant> commands = commandFrequency.get(sourceId);
        commands.add(timestamp);
        commands.removeIf(t -> Duration.between(t, timestamp).toSeconds() > 30);
        if (commands.size() > 10) {
            logAlert("ALERT: Device spam detected from: " + sourceId);
        }
    }

    private static void detectAbnormalPower(String deviceId, Map<String, Object> context) {
        double value = (double) context.getOrDefault("value", 0.0);
        powerReadings.putIfAbsent(deviceId, new ArrayList<>());
        List<Double> readings = powerReadings.get(deviceId);
        readings.add(value);
        if (readings.size() > 50) readings.remove(0);

        double avg = readings.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        if (value < 0 || value > 1.5 * avg) {
            logAlert("ALERT: Abnormal power reading from: " + deviceId + " - value: " + value);
        }
    }

    private static void detectSuspiciousTempControl(String sourceId, Instant timestamp) {
        commandFrequency.putIfAbsent(sourceId + "_temp", new ArrayList<>());
        List<Instant> changes = commandFrequency.get(sourceId + "_temp");
        changes.add(timestamp);
        changes.removeIf(t -> Duration.between(t, timestamp).toSeconds() > 20);
        if (changes.size() > 5) {
            logAlert("ALERT: Rapid temperature control changes from: " + sourceId);
        }
    }

    private static void detectUnauthorizedAccess(String userId, String userRole, Map<String, Object> context) {
        String requestedAccess = (String) context.getOrDefault("resource", "");
        boolean privileged = requestedAccess.equals("security_camera") || requestedAccess.equals("admin_panel");
        if (privileged && !userRole.equals("ADMIN")) {
            logAlert("ALERT: Unauthorized access attempt by user: " + userId);
        }
    }

    private static void logAlert(String message) {
        alertLog.add("[ALERT] " + Instant.now() + " - " + message);
        System.out.println(message);
    }

    private static void logEvent(String message) {
        System.out.println("[LOG] " + Instant.now() + " - " + message);
    }

    public static void showAlerts() {
        System.out.println("\n--- Alert Log ---");
        for (String alert : alertLog) {
            System.out.println(alert);
        }
    }

    // Test harness
    public static void main(String[] args) throws InterruptedException {
        Instant now = Instant.now();

        // Normal login usage
        for (int i = 0; i < 3; i++) {
            instrument("login_attempt", "USER", "u1", "ip1", now, Map.of("success", false));
            Thread.sleep(500);
        }

        // Simulated brute-force login attack
        for (int i = 0; i < 6; i++) {
            instrument("login_attempt", "USER", "u1", "ip2", now.plusSeconds(i * 5), Map.of("success", false));
        }

        // Normal toggle
        for (int i = 0; i < 3; i++) {
            instrument("toggle_device", "USER", "u2", "dev1", now.plusSeconds(i), Map.of());
        }

        // Command spam
        for (int i = 0; i < 11; i++) {
            instrument("toggle_device", "USER", "u2", "dev2", now.plusSeconds(i), Map.of());
        }

        // Abnormal power
        for (int i = 0; i < 50; i++) {
            instrument("power_reading", "USER", "u3", "powerDev", now, Map.of("value", 100.0));
        }
        instrument("power_reading", "USER", "u3", "powerDev", now, Map.of("value", 200.0));

        // Rapid temperature changes
        for (int i = 0; i < 6; i++) {
            instrument("temperature_change", "USER", "u4", "thermo1", now.plusSeconds(i * 3), Map.of());
        }

        // Unauthorized access
        instrument("unauthorized_access", "USER", "u5", "ipX", now, Map.of("resource", "security_camera"));

        showAlerts();
    }
}
