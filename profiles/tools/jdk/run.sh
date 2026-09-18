#!/bin/bash
# Profile: JDK diagnostic tools (jcmd, jstack, jps).
# Other JDK tools (jmap, jinfo, jstat, jfr, jhsdb) use the same attach
# mechanism and are not tested separately since the syscall pattern is
# identical: write to /proc/<pid>/cwd/.attach_pid<pid>.
[ "$1" = "--check" ] && { command -v java >/dev/null; exit; }

# Start a background Java process to attach to.
java -cp . -Xmx8m -XX:-UseCompressedOops -XX:+UseSerialGC \
  --source 11 /dev/stdin <<'JAVA' &
public class Spin { public static void main(String[] a) throws Exception { Thread.sleep(30000); } }
JAVA
JPID=$!
sleep 2

jps -l
jcmd "$JPID" VM.version
jcmd "$JPID" Thread.print
jstack "$JPID"

kill "$JPID" 2>/dev/null
wait "$JPID" 2>/dev/null
