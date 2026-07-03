package dev.reachlayer.reach.entrypoints;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

class EntryPointScannerTest {

    @TempDir Path tempDir;

    @Test
    void discoversPublicStaticVoidMain() throws IOException {
        writeClass(
                tempDir,
                "com/example/App",
                cw -> {
                    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/App", null, "java/lang/Object", null);
                    writeDefaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv =
                            cw.visitMethod(
                                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                                    "main",
                                    "([Ljava/lang/String;)V",
                                    null,
                                    null);
                    mv.visitCode();
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();
                });

        List<EntryPoint> found = new EntryPointScanner().discover(tempDir);

        assertThat(found)
                .anySatisfy(
                        ep -> {
                            assertThat(ep.className()).isEqualTo("com.example.App");
                            assertThat(ep.methodName()).isEqualTo("main");
                        });
    }

    @Test
    void discoversSpringMvcHandlerMethodsOnRestControllersOnly() throws IOException {
        writeClass(
                tempDir,
                "com/example/GreetController",
                cw -> {
                    cw.visit(
                            Opcodes.V17,
                            Opcodes.ACC_PUBLIC,
                            "com/example/GreetController",
                            null,
                            "java/lang/Object",
                            null);
                    cw.visitAnnotation("Lorg/springframework/web/bind/annotation/RestController;", true)
                            .visitEnd();
                    writeDefaultConstructor(cw, "java/lang/Object");

                    MethodVisitor mapped =
                            cw.visitMethod(Opcodes.ACC_PUBLIC, "greet", "()Ljava/lang/String;", null, null);
                    mapped.visitAnnotation("Lorg/springframework/web/bind/annotation/GetMapping;", true)
                            .visitEnd();
                    mapped.visitCode();
                    mapped.visitInsn(Opcodes.ACONST_NULL);
                    mapped.visitInsn(Opcodes.ARETURN);
                    mapped.visitMaxs(0, 0);
                    mapped.visitEnd();

                    // Unannotated method on the same controller must NOT be picked up.
                    MethodVisitor plain = cw.visitMethod(Opcodes.ACC_PUBLIC, "helper", "()V", null, null);
                    plain.visitCode();
                    plain.visitInsn(Opcodes.RETURN);
                    plain.visitMaxs(0, 0);
                    plain.visitEnd();
                });

        List<EntryPoint> found = new EntryPointScanner().discover(tempDir);

        assertThat(found).hasSize(1);
        assertThat(found.get(0).className()).isEqualTo("com.example.GreetController");
        assertThat(found.get(0).methodName()).isEqualTo("greet");
    }

    @Test
    void discoversServletDoGetOverridesOnDirectHttpServletSubclasses() throws IOException {
        writeClass(
                tempDir,
                "com/example/MyServlet",
                cw -> {
                    cw.visit(
                            Opcodes.V17,
                            Opcodes.ACC_PUBLIC,
                            "com/example/MyServlet",
                            null,
                            "jakarta/servlet/http/HttpServlet",
                            null);
                    writeDefaultConstructor(cw, "jakarta/servlet/http/HttpServlet");
                    MethodVisitor mv =
                            cw.visitMethod(
                                    Opcodes.ACC_PROTECTED,
                                    "doGet",
                                    "(Ljakarta/servlet/http/HttpServletRequest;"
                                            + "Ljakarta/servlet/http/HttpServletResponse;)V",
                                    null,
                                    null);
                    mv.visitCode();
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();
                });

        List<EntryPoint> found = new EntryPointScanner().discover(tempDir);

        assertThat(found)
                .anySatisfy(
                        ep -> {
                            assertThat(ep.className()).isEqualTo("com.example.MyServlet");
                            assertThat(ep.methodName()).isEqualTo("doGet");
                        });
    }

    @Test
    void ignoresPlainClassesWithNoEntryPoints() throws IOException {
        writeClass(
                tempDir,
                "com/example/PlainService",
                cw -> {
                    cw.visit(
                            Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/PlainService", null, "java/lang/Object", null);
                    writeDefaultConstructor(cw, "java/lang/Object");
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "doWork", "()V", null, null);
                    mv.visitCode();
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();
                });

        assertThat(new EntryPointScanner().discover(tempDir)).isEmpty();
    }

    private static void writeDefaultConstructor(ClassWriter cw, String superInternalName) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, superInternalName, "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
    }

    private interface ClassBuilder {
        void build(ClassWriter cw);
    }

    private static void writeClass(Path root, String internalName, ClassBuilder builder) throws IOException {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        builder.build(cw);
        cw.visitEnd();
        Path target = root.resolve(internalName + ".class");
        Files.createDirectories(target.getParent());
        Files.write(target, cw.toByteArray());
    }
}
