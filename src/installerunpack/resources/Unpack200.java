import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

// Batch bridge to the separately supplied open-source Glavo Pack200 library.
// Runs decoder code only; no classes from input JARs are loaded or executed.
class Unpack200 {
    public static void main(String[] args) throws Exception {
        Class<?> api = Class.forName("org.glavo.pack200.Pack200");
        Class<?> unpacker = Class.forName("org.glavo.pack200.Pack200$Unpacker");
        java.lang.reflect.Method method = unpacker.getMethod("unpack", InputStream.class, JarOutputStream.class);
        List<String> lines = Files.readAllLines(Paths.get(args[0]));
        for (int i = 0; i < lines.size(); i += 2) {
            Path source = Paths.get(new String(Base64.getDecoder().decode(lines.get(i)), "UTF-8"));
            Path target = Paths.get(new String(Base64.getDecoder().decode(lines.get(i + 1)), "UTF-8"));
            try (BufferedInputStream raw = new BufferedInputStream(Files.newInputStream(source))) {
                raw.mark(2);
                int a = raw.read(), b = raw.read(); raw.reset();
                InputStream input = a == 31 && b == 139 ? new GZIPInputStream(raw) : raw;
                try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(target, StandardOpenOption.CREATE_NEW))) {
                    method.invoke(api.getMethod("newUnpacker").invoke(null), input, output);
                }
            } catch (Exception error) {
                Files.deleteIfExists(target);
                System.err.println(source + ": " + error.toString());
            }
        }
    }
}
