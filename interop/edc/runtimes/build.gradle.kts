// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

// Shared settings of the three EDC runtimes. Each is one runnable jar
// ("shadow" jar), started with EDC's BaseRuntime.

plugins {
    java
    // builds the one-file runnable jar, as the EDC launchers do
    id("com.gradleup.shadow") version "9.5.1" apply false
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "application")
    apply(plugin = "com.gradleup.shadow")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    extensions.configure<JavaApplication> {
        mainClass.set("org.eclipse.edc.boot.system.runtime.BaseRuntime")
    }

    tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
        // EDC finds its extensions through META-INF/services files
        mergeServiceFiles()
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
        archiveFileName.set("${project.name}.jar")
    }
}
