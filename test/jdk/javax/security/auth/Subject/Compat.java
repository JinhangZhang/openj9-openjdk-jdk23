/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
import com.sun.security.auth.UserPrincipal;

import javax.security.auth.Subject;
import javax.security.auth.SubjectDomainCombiner;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.util.Objects;

/*
 * @test
 * @bug 8296244
 * @run main/othervm -Djava.security.manager=allow Compat
 * @summary ensures the old implementation still works when SM is allowed
 */
public class Compat {

    // 当 action.run() 被执行时，它会返回当前线程的 AccessControlContext。这个上下文包括以下内容：
    // 1. 当前线程的权限信息：
    //    AccessControlContext 包含了当前线程的所有 ProtectionDomain，这些域定义了线程可以执行哪些操作。
    //    每个 ProtectionDomain 都与一个特定的代码来源（例如 JAR 文件）相关联，并描述了该来源所拥有的权限。
    // 2. 当前线程的调用堆栈：
    //    AccessControlContext 还包括了当前线程的调用堆栈信息。
    //    这意味着在权限检查时，Java 安全模型会检查调用链中的所有 ProtectionDomain，以确定是否允许执行某个操作。
    // 3. 当前 Subject 的信息（如果存在）：
    //    如果当前线程是通过 Subject.doAs 或 Subject.doAsPrivileged 执行的，那么 AccessControlContext 还会包含与该 Subject 相关的权限信息。
    //    这意味着 AccessControlContext 可能还包含与 Subject 相关的 Principal 和 Credentials。
    static PrivilegedExceptionAction<AccessControlContext> action
            = () -> AccessController.getContext();

    static boolean failed = false;

    public static void main(String[] args) throws Exception {
        System.out.println("Start main0(null)...");
        main0(null);
        System.out.println("Prepare a new thread for main0(null)...");
        var t = new Thread(() -> {
            try {
                System.out.println("Start a new thread for main0(null)...");
                main0(null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        t.start();
        t.join(); // 这行代码使主线程等待线程 t 完成。join() 方法会阻塞主线程，直到线程 t 结束执行
        System.out.println("main thread main0(null) is finished.");
    }
    public static void main0(String[] args) throws Exception {
        System.out.println(">>> bare run");
        run(null);
        System.out.println(">>> run inside");
        Subject subject = makeSubject("three");
        Subject.doAs(subject, (PrivilegedExceptionAction<? extends Object>)
                () -> run("three"));
        if (failed) {
            throw new RuntimeException();
        }
    }

    public static Void run(String from) throws Exception {
        Subject subject = makeSubject("one");
        var a1 = Subject.doAs(subject, action);
        Subject subject2 = makeSubject("two");

        var a2 = Subject.doAs(subject2, action);

        test("from ether", AccessController.getContext(), from);
        test("from a1", a1, "one");
        test("from a2", a2, "two");

        var a3 = Subject.doAsPrivileged(subject, action, a1);
        test("doAsPriv with one and a1", a3, "one");

        // Subject.doAsPrivileged方法会优先使用 subject 的权限上下文（即 "one"），然后再结合 a2 进行操作。
        // 即使 a2 中可能有其他的 Subject 信息（如 "two"），但是 Subject.doAsPrivileged 的特性是优先使用指定的 Subject，即 "one"。
        // subject（即 "one"）是当前操作的主要 Subject，即使结合了 a2 作为额外的上下文，它也不会覆盖或替换 subject 中的 Subject。
        // a2 的作用是作为补充的权限上下文，而不是改变 Subject 的身份。
        var a4 = Subject.doAsPrivileged(subject, action, a2);
        test("doAsPriv with one and a2", a4, "one");

        var a5 = Subject.doAsPrivileged(null, action, a2); // 是因为这里提供的是非subject- related的上下文，所以返回的是null吗？
        test("doAsPriv with null and a2", a5, null);

        var a6 = Subject.doAs(null, action);
        test("doAsPriv with null and this", a6, null);

        var ax = new AccessControlContext(a2, new SubjectDomainCombiner(subject));
        test("a2 plus subject", ax, "one");

            ax = AccessController.doPrivileged(action, a2);
            test("doPriv on a2", ax, "two");

        ax = AccessController.doPrivilegedWithCombiner(action);
        test("doPrivWC", ax, from == null ? null : from);

        ax = AccessController.doPrivilegedWithCombiner(action, a2);
        test("doPrivWC on a2", ax, from == null ? "two" : "three");
        return null;
    }

    static Subject makeSubject(String name) {
        Subject subject = new Subject();
        subject.getPrincipals().add(new UserPrincipal(name));
        return subject;
    }

    static String getSubject(AccessControlContext acc) {
        var subj = Subject.getSubject(acc);
        if (subj == null) return null;
        var princ = subj.getPrincipals(UserPrincipal.class);
        return (princ == null || princ.isEmpty())
                ? null
                : princ.iterator().next().getName();
    }

    static void test(String label, AccessControlContext acc, String expected) {
        var actual = getSubject(acc);
        System.out.println(label + ": " + actual);
        if (!Objects.equals(actual, expected)) {
            System.out.println("    Expect " + expected + ", but see " + actual);
            failed = true;
        }
    }
}
