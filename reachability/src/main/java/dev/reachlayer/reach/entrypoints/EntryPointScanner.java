package dev.reachlayer.reach.entrypoints;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Discovers application entry points — methods the runtime can invoke directly rather than only
 * via other application code — by scanning compiled bytecode structurally.
 *
 * <p><b>Implementation choice:</b> entry-point discovery only needs a class's raw structure
 * (superclass name, method names/descriptors, annotation descriptors); it never needs a resolved
 * type hierarchy or method bodies. ASM ({@code org.ow2.asm}) reads that directly and predictably
 * from individual {@code .class} files without requiring a fully-linked SootUp {@code JavaView}
 * (which needs a resolvable classpath before it will open anything, and is comparatively heavy
 * machinery for what is otherwise a simple bytecode-attribute scan). SootUp itself is reserved for
 * {@link dev.reachlayer.reach.callgraph.CallGraphBuilder}, where the actual call-graph traversal
 * happens and a resolved view is genuinely required. ASM also never needs the annotation types
 * themselves (e.g. Spring) to be present on this module's own classpath — it only reads their
 * descriptor strings out of the class file's constant pool.
 *
 * <p>Detects three kinds of entry points (PLAN.md §4, §7):
 *
 * <ul>
 *   <li>{@code public static void main(String[])}
 *   <li>methods on classes annotated {@code @Controller} or {@code @RestController} that are
 *       themselves annotated with a Spring MVC mapping annotation ({@code @RequestMapping},
 *       {@code @GetMapping}, {@code @PostMapping}, {@code @PutMapping}, {@code @DeleteMapping},
 *       {@code @PatchMapping})
 *   <li>{@code doGet}/{@code doPost}/... methods on a direct subclass of {@code HttpServlet}
 *       ({@code javax} or {@code jakarta} package)
 * </ul>
 *
 * <p><b>Known limitation:</b> the servlet check only looks at the immediate superclass named in
 * the class file, not the full (possibly multi-level) inheritance chain — a servlet base class two
 * or more levels removed from {@code HttpServlet} will not be detected. This is a deliberately
 * conservative MVP heuristic, not a soundness guarantee (see PLAN.md §9 risk 1: prefer under- over
 * over-claiming).
 */
public final class EntryPointScanner {

    private static final Logger log = LoggerFactory.getLogger(EntryPointScanner.class);

    private static final Set<String> CONTROLLER_ANNOTATIONS =
            Set.of(
                    "Lorg/springframework/stereotype/Controller;",
                    "Lorg/springframework/web/bind/annotation/RestController;");

    private static final Set<String> MAPPING_ANNOTATIONS =
            Set.of(
                    "Lorg/springframework/web/bind/annotation/RequestMapping;",
                    "Lorg/springframework/web/bind/annotation/GetMapping;",
                    "Lorg/springframework/web/bind/annotation/PostMapping;",
                    "Lorg/springframework/web/bind/annotation/PutMapping;",
                    "Lorg/springframework/web/bind/annotation/DeleteMapping;",
                    "Lorg/springframework/web/bind/annotation/PatchMapping;");

    private static final Set<String> SERVLET_SUPERCLASSES =
            Set.of("javax/servlet/http/HttpServlet", "jakarta/servlet/http/HttpServlet");

    private static final Set<String> SERVLET_METHOD_NAMES =
            Set.of("doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace");

    /**
     * Scans every {@code .class} file under {@code classesRoot} (a directory, walked recursively,
     * or a {@code .jar} file) and returns the entry points found. Individual unreadable/corrupt
     * class files are skipped (logged at debug level) rather than failing the whole scan.
     */
    public List<EntryPoint> discover(Path classesRoot) throws IOException {
        List<EntryPoint> found = new ArrayList<>();
        if (Files.isDirectory(classesRoot)) {
            try (Stream<Path> paths = Files.walk(classesRoot)) {
                List<Path> classFiles = paths.filter(p -> p.toString().endsWith(".class")).toList();
                for (Path path : classFiles) {
                    try (InputStream in = Files.newInputStream(path)) {
                        scanClass(in, found);
                    } catch (Exception e) {
                        log.debug("Skipping unreadable class file {}: {}", path, e.toString());
                    }
                }
            }
        } else if (classesRoot.toString().toLowerCase(Locale.ROOT).endsWith(".jar")) {
            try (JarFile jar = new JarFile(classesRoot.toFile())) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                        continue;
                    }
                    try (InputStream in = jar.getInputStream(entry)) {
                        scanClass(in, found);
                    } catch (Exception e) {
                        log.debug("Skipping unreadable jar entry {}: {}", entry.getName(), e.toString());
                    }
                }
            }
        } else {
            throw new IOException("Unsupported classes root (not a directory or .jar file): " + classesRoot);
        }
        return found;
    }

    private void scanClass(InputStream in, List<EntryPoint> out) throws IOException {
        ClassReader reader = new ClassReader(in);
        reader.accept(
                new EntryPointClassVisitor(out),
                ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }

    private static final class EntryPointClassVisitor extends ClassVisitor {
        private final List<EntryPoint> out;
        private String className;
        private boolean controllerClass;
        private boolean servletSubclass;

        EntryPointClassVisitor(List<EntryPoint> out) {
            super(Opcodes.ASM9);
            this.out = out;
        }

        @Override
        public void visit(
                int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
            this.servletSubclass = superName != null && SERVLET_SUPERCLASSES.contains(superName);
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            if (CONTROLLER_ANNOTATIONS.contains(descriptor)) {
                controllerClass = true;
            }
            return null;
        }

        @Override
        public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature, String[] exceptions) {
            boolean isMain =
                    "main".equals(name)
                            && "([Ljava/lang/String;)V".equals(descriptor)
                            && (access & Opcodes.ACC_PUBLIC) != 0
                            && (access & Opcodes.ACC_STATIC) != 0;
            if (isMain) {
                out.add(new EntryPoint(className, name, "public static void main(String[])"));
            }
            if (servletSubclass && SERVLET_METHOD_NAMES.contains(name)) {
                out.add(new EntryPoint(className, name, "overrides HttpServlet." + name));
            }
            if (controllerClass) {
                String methodName = name;
                return new MethodVisitor(Opcodes.ASM9) {
                    private boolean mapped;

                    @Override
                    public AnnotationVisitor visitAnnotation(String annDescriptor, boolean annVisible) {
                        if (MAPPING_ANNOTATIONS.contains(annDescriptor)) {
                            mapped = true;
                        }
                        return null;
                    }

                    @Override
                    public void visitEnd() {
                        if (mapped) {
                            out.add(new EntryPoint(className, methodName, "Spring MVC handler method"));
                        }
                    }
                };
            }
            return null;
        }
    }
}
