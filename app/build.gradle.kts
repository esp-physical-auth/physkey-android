import org.jetbrains.kotlin.gradle.dsl.JvmTarget

val rustCrateDir = rootDir.resolve("../physkey-linux/esp32-fido-core").normalize()
val rustWorkspaceDir = rootDir.resolve("../physkey-linux").normalize()
val cargoBin = findProperty("cargoNdk.command") as? String ?: "cargo"
val localPropsFile = rootDir.resolve("local.properties")
val ndkFromLocalProps = if (localPropsFile.exists()) {
    localPropsFile.readLines()
        .firstOrNull { it.startsWith("ndk.dir=") }
        ?.substringAfter("ndk.dir=")
} else null
val androidNdkHome = System.getenv("ANDROID_NDK_HOME") ?: ndkFromLocalProps
val rustTargets = listOf(
    "aarch64-linux-android"  to "arm64-v8a",
    "armv7-linux-androideabi" to "armeabi-v7a",
    "x86_64-linux-android"    to "x86_64",
)

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "pl.lebihan.authnkey"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "pl.lebihan.authnkey"
        minSdk = 34
        targetSdk = 37
        versionCode = 13
        versionName = "1.2.6"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            isShrinkResources = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    androidResources {
        @Suppress("UnstableApiUsage")
        generateLocaleConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_17
        }
    }
}

tasks.register("buildRustLib") {
    group = "rust"
    description = "编译 esp32-fido-core .so 并复制到 jniLibs"
    outputs.upToDateWhen { false }
    doLast {
        val ndk = androidNdkHome
            ?: throw GradleException("未找到 ANDROID_NDK_HOME 或 ndk.dir（local.properties）")
        rustTargets.forEach { (target, abi) ->
            val cmd = listOf(
                cargoBin, "ndk",
                "--manifest-path", "$rustCrateDir/Cargo.toml",
                "--target", target,
                "--", "build", "--release",
                "--features", "jni",
                "--lib",
            )
            val pb = ProcessBuilder(cmd)
                .directory(rustCrateDir)
                .redirectErrorStream(true)
            pb.environment()["ANDROID_NDK_HOME"] = ndk
            val proc = pb.start()
            proc.inputStream.bufferedReader().forEachLine { println("[rust:$target] $it") }
            val rc = proc.waitFor()
            if (rc != 0) throw GradleException("cargo ndk build failed for $target (exit=$rc)")
            val src = file("$rustWorkspaceDir/target/$target/release/libesp32_fido_core.so")
            if (!src.exists()) throw GradleException("未找到编译产物: ${src.absolutePath}")
            val dst = file("src/main/jniLibs/$abi/libesp32_fido_core.so")
            dst.parentFile.mkdirs()
            src.copyTo(dst, overwrite = true)
            println("[rust] installed ${src.name} → ${dst.parentFile.name}/ (${src.length()} bytes)")
        }
    }
}

tasks.matching { it.name.startsWith("assemble") }.configureEach {
    dependsOn("buildRustLib")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.credentials)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.material)

    implementation("androidx.lifecycle:lifecycle-process:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
}