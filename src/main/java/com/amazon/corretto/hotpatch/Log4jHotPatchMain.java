package com.amazon.corretto.hotpatch;

import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;

import static com.amazon.corretto.hotpatch.Constants.LOG4J_FIXER_AGENT_VERSION;
import static com.amazon.corretto.hotpatch.Util.log;

public class Log4jHotPatchMain {
    public static void main(String[] args) throws Exception {
        String[] pidArgs = Arrays.stream(args).filter(it -> !it.startsWith("-")).toArray(String[]::new);
        String[] otherArgs = Arrays.stream(args).filter(it -> it.startsWith("-")).toArray(String[]::new);
        if (args.length == 0) {
            MonitoredHost host = MonitoredHost.getMonitoredHost((String)null);
            Set<Integer> pids = host.activeVms();
            pidArgs = new String[pids.size()];
            int count = 0;
            for (Integer p : pids) {
                MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(p.toString()));
                String mainClass = MonitoredVmUtil.mainClass(jvm, true);
                if (!MY_NAME.equals(mainClass)) {
                    log(p + ": " + mainClass);
                    pidArgs[count++] = p.toString();
                }
            }
            if (count > 0) {
                log("Patching all JVMs!");
            }
        } else if (args.length == 1 && ("-version".equals(args[0]) || "--version".equals(args[0]))) {
            String title = Log4jHotPatchMain.class.getPackage().getImplementationTitle();
            String version = Log4jHotPatchMain.class.getPackage().getImplementationVersion();
            String vendor = Log4jHotPatchMain.class.getPackage().getImplementationVendor();
            System.out.println(title + " by " + vendor);
            System.out.println("Version: " + version);
            System.exit(0);
            return;
        } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
            String title = Log4jHotPatchMain.class.getPackage().getImplementationTitle();
            String version = Log4jHotPatchMain.class.getPackage().getImplementationVersion();
            String vendor = Log4jHotPatchMain.class.getPackage().getImplementationVendor();
            System.out.println(title + " by " + vendor);
            System.out.println("Version: " + version);
            String jarName = new File(Log4jHotPatchMain.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getName();
            System.out.println("usage: java -jar " + jarName + " [<pid> [<pid> ..]]");
            System.exit(1);
            return;
        }
        boolean succeeded = loadInstrumentationAgent(pidArgs, otherArgs);
        if (succeeded) {
            System.exit(0);
        } else {
            log("Errors occurred deploying hot patch. If you are using java 8 to run this\n" +
                    "tool against JVM 11 or later, the target JVM may still be patched. Please look for a message\n" +
                    "like 'Loading Java Agent (using ASM 6).' in stdout of the target JVM. Also note that JVM 17+\n" +
                    "are not supported.");
            System.exit(1);
        }
    }

    private static final String MY_NAME = Log4jHotPatchAgent.class.getName();

    private static boolean loadInstrumentationAgent(String[] pids, String[] otherArgs) throws Exception {
        boolean succeeded = true;
        File jarFile = new File(Log4jHotPatchMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        String we = getUID("self");
        for (String pid : pids) {
            if (pid != null) {
                try {
                    // Check if we're running under the same UID like the target JVM.
                    // If not, log warning as it might fail to attach.
                    if (we != null && !we.equals(getUID(pid))) {
                        log("\nWarning: patching for JVM process " + pid + " might fail because it runs under a different user");
                        log("  Our uid == " + we + ", their uid == " + getUID(pid));
                    }

                    VirtualMachine vm = VirtualMachine.attach(pid);

                    // If the target VM is already patched then skip.
                    // Notice that the agent class gets loaded by the system class loader, so we
                    // can't unload or update it. If we'd re-deploy the agent one more time, we'd
                    // just rerun 'agentmain()' from the already loaded agent version.
                    Properties props = vm.getSystemProperties();
                    if (props == null) {
                        log("Error: could not verify 'log4jFixerAgentVersion' in JVM process " + pid);
                        continue;
                    }
                    String version = props.getProperty(LOG4J_FIXER_AGENT_VERSION);
                    if(version != null) {
                        log("Skipping patch for JVM process " + pid + ", patch version " + version + " already applied");
                        continue;
                    }
                    // unpatched target VM, apply patch
                    String args = String.join(" ", Util.getVerboseString(), String.join(" ", otherArgs));
                    vm.loadAgent(jarFile.getAbsolutePath(), args);
                } catch (Exception e) {
                    succeeded = false;
                    log(e);
                    log("Error: couldn't loaded the agent into JVM process " + pid);
                    log("  Are you running as a different user (including root) than process " + pid + "?");
                    continue;
                }
                log("Successfully loaded the agent into JVM process " + pid);
                log("  Look at stdout of JVM process " + pid + " for more information");
            }
        }
        return succeeded;
    }

    // This only works on Linux, but it is harmless as it returns 'null'
    // on error and null values for the UID will be ignored later on.
    private static String getUID(String pid) {
        try {
            return Files.lines(FileSystems.getDefault().getPath("/proc/" + pid + "/status")).
                    filter(l -> l.startsWith("Uid:")).
                    findFirst().get().split("\\s")[1];
        } catch (Exception e) {
            return null;
        }
    }
}
