pipeline {
    agent any
    
    environment {
        PROJECTNAME = 'casspeed'
        CGO_ENABLED = '0'
        VERSION = sh(returnStdout: true, script: 'git describe --tags --always').trim()
        COMMIT_ID = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
        BUILD_DATE = sh(returnStdout: true, script: 'date +"%a %b %d, %Y at %H:%M:%S %Z"').trim()
    }
    
    stages {
        stage('Setup') {
            steps {
                echo "Building ${PROJECTNAME} version ${VERSION}"
                sh 'mkdir -p binaries releases'
            }
        }
        
        stage('Build All Platforms') {
            parallel {
                stage('Linux AMD64') {
                    steps {
                        sh '''
                            GOOS=linux GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-linux-amd64 ./src
                            GOOS=linux GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-linux-amd64 ./src/client
                        '''
                    }
                }
                stage('Linux ARM64') {
                    steps {
                        sh '''
                            GOOS=linux GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-linux-arm64 ./src
                            GOOS=linux GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-linux-arm64 ./src/client
                        '''
                    }
                }
                stage('macOS AMD64') {
                    steps {
                        sh '''
                            GOOS=darwin GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-darwin-amd64 ./src
                            GOOS=darwin GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-darwin-amd64 ./src/client
                        '''
                    }
                }
                stage('macOS ARM64') {
                    steps {
                        sh '''
                            GOOS=darwin GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-darwin-arm64 ./src
                            GOOS=darwin GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-darwin-arm64 ./src/client
                        '''
                    }
                }
                stage('Windows AMD64') {
                    steps {
                        sh '''
                            GOOS=windows GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-windows-amd64.exe ./src
                            GOOS=windows GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-windows-amd64.exe ./src/client
                        '''
                    }
                }
                stage('Windows ARM64') {
                    steps {
                        sh '''
                            GOOS=windows GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-windows-arm64.exe ./src
                            GOOS=windows GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-windows-arm64.exe ./src/client
                        '''
                    }
                }
                stage('FreeBSD AMD64') {
                    steps {
                        sh '''
                            GOOS=freebsd GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-freebsd-amd64 ./src
                            GOOS=freebsd GOARCH=amd64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-freebsd-amd64 ./src/client
                        '''
                    }
                }
                stage('FreeBSD ARM64') {
                    steps {
                        sh '''
                            GOOS=freebsd GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-freebsd-arm64 ./src
                            GOOS=freebsd GOARCH=arm64 go build \
                                -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildDate=${BUILD_DATE}'" \
                                -o binaries/${PROJECTNAME}-cli-freebsd-arm64 ./src/client
                        '''
                    }
                }
            }
        }
        
        stage('Test') {
            steps {
                sh 'go test -v ./...'
            }
        }
        
        stage('Archive') {
            when {
                anyOf {
                    branch 'main'
                    tag pattern: 'v*', comparator: 'REGEXP'
                }
            }
            steps {
                archiveArtifacts artifacts: 'binaries/*', fingerprint: true
            }
        }
    }
    
    post {
        success {
            echo "Build completed successfully for ${PROJECTNAME} ${VERSION}"
        }
        failure {
            echo "Build failed for ${PROJECTNAME} ${VERSION}"
        }
        cleanup {
            cleanWs()
        }
    }
}
