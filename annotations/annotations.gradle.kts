plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

group = "org.zaproxy"
version = "1.0-SNAPSHOT"

dependencies {
    compileOnly("com.google.auto.service:auto-service:1.1.1") // optional helper
    annotationProcessor("com.google.auto.service:auto-service:1.1.1")
}

/* TODO this causes the compilation to fail
tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-parameters,-Xlint:all,-serial,-processing")
}
*/

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs = options.compilerArgs + "-Xlint:all,-serial,-processing"
    // options.compilerArgs.add("-parameters")
    // options.compilerArgs.add("-Xlint:all,-serial,-processing")
    // options.compilerArgs.add("-Xlint:all")
}
