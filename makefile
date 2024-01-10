CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS =

CRYPTO_DIR = ARIA
SERVER_SRCS = server.cpp
CLIENT_SRCS = client.cpp $(CRYPTO_DIR)/aria_gcm.cpp $(CRYPTO_DIR)/aria.cpp
SERVER_OBJS = $(SERVER_SRCS:.cpp=.o)
CLIENT_OBJS = $(CLIENT_SRCS:.cpp=.o)
SERVER_EXEC = server
CLIENT_EXEC = client

all: $(SERVER_EXEC) $(CLIENT_EXEC)

$(SERVER_EXEC): $(SERVER_OBJS)
	$(CXX) $(LDFLAGS) $(SERVER_OBJS) -o $(SERVER_EXEC)

$(CLIENT_EXEC): $(CLIENT_OBJS)
	$(CXX) $(LDFLAGS) $(CLIENT_OBJS) -o $(CLIENT_EXEC)

# 오브젝트 파일 생성 규칙
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ -I$(CRYPTO_DIR)

# clean 규칙
clean:
	rm -f $(SERVER_OBJS) $(CLIENT_OBJS) $(SERVER_EXEC) $(CLIENT_EXEC)
