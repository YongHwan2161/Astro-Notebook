#include <vector>
#include <stack>
#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <locale>
#include <codecvt>
#include <sys/socket.h>
#include <thread>

#define PORT 8080
using namespace std;
using uint = unsigned int;
using ushort = unsigned short;
using uchar = unsigned char;

int Network()
{
    struct sockaddr_in server_addr;
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        std::cerr << "Server socket creation failed.\n";
        return -1;
    }
    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080); // 포트 번호는 8080으로 설정
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        std::cerr << "setsockopt error.\n";
        return -1;
    }
    // 서버 소켓에 주소 바인드
    if (::bind(serverSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        std::cerr << "Bind error.\n";
        return -1;
    }
    // 클라이언트의 연결 요청을 대기
    if (listen(serverSocket, 5) == -1)
    {
        std::cerr << "Listen error.\n";
        return -1;
    }
    while (true)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        client_socket = accept(serverSocket, (struct sockaddr *)&client_addr, &client_addr_size);

        if (client_socket == -1)
        {
            std::cerr << "Accept error.\n";
            continue;
        }

        // 클라이언트와의 통신을 위한 코드를 여기에 작성하세요.
        char buffer[20000];
        int bytesReceived = recv(client_socket, buffer, sizeof(buffer) - 1, 0); // Leave space for null terminator
        if (bytesReceived > 0)
        {
            std::string request(buffer);
            buffer[bytesReceived] = '\0'; // Null-terminate the received data
                                          // Create a wide string converter
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

            // Convert the multibyte string to a wide string
            std::wstring ws = converter.from_bytes(buffer);
            // std::cerr << "Received message: " << wstringToUtf8(ws) << std::endl;
            //  wchar_t type3[1024];
            //  int charsConverted = MultiByteToWideChar(CP_UTF8, 0, buffer, bytesReceived, type3, sizeof(type3) / sizeof(wchar_t));
            wstring firstLine = ws.substr(0, ws.find(L"\r\n"));
            wstring method = firstLine.substr(0, firstLine.find(L" HTTP"));
            wstring content = L"";
            if (method == L"GET /")
            {
                // std::cerr << "get GET request" << std::endl;
                std::ifstream file("index2.html");
                if (!file.is_open())
                {
                    std::cerr << "Failed to open file" << std::endl;
                    continue; // Skip this iteration
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
                send(client_socket, response.c_str(), response.size(), 0);
            }
            if (startsWith(method, L"GET /checkDuplicate") == true)
            {
                string response = "";
                response = handle_check_duplicate(request);
                send(client_socket, response.c_str(), response.size(), 0);
            }
            else if (method == L"POST /login")
            {
                auto contentPos = request.find("\r\n\r\n");
                if (contentPos != std::string::npos)
                {
                    std::string postData = request.substr(contentPos + 4);
                    handleLogin(postData, client_socket);
                }
            }
            else if (method == L"POST /signup")
            {
                auto headerEndPos = request.find("\r\n\r\n");
                if (headerEndPos != std::string::npos)
                {
                    std::string requestBody = request.substr(headerEndPos + 4);
                    handleSignUp(requestBody, client_socket);
                }
            }
            else if (method == L"POST /" || method == L"POST /8080")
            {
                std::cerr << "get POST request!!!" << std::endl;
                std::wstring prefix = L"\r\n\r\n";
                size_t startPos = ws.find(prefix);
                if (startPos != std::wstring::npos)
                {
                    wstring clientMessage = ws.substr(startPos + 4);
                    // std::cerr << "clientMessage: " << wstringToUtf8(clientMessage) << std::endl;
                    std::vector<std::wstring> clientMvec = splitWstring(clientMessage, L"\t");
                    std::cerr << "clientMvec[0]: " << wstringToUtf8(clientMvec[0]) << endl;
                    wstringstream wss(clientMvec[0]);
                    std::wstring userString = wss.str(); // 스트림 내용을 wstring으로 변환
                    wss >> user;
                    std::cerr << "user = " << wstringToUtf8(userString) << std::endl;
                    if (user == 0)
                    { // 처음 접속 시 보내는 내용(로그인 화면)
                        std::cerr << "user == 0" << std::endl;
                        if (clientMvec[1] == L"0")
                        {
                            cerr << "첫 화면" << endl;
                            uchar *sheet34198 = Sheet(34198);
                            wcout << L"Sheet(34198) =" << charToWstring(sheet34198) << endl;
                            content = intToWString(user) + L"\t" + intToWString(34198) + L"\t" + L"0" + L"\t" + charToWstring(sheet34198) + L"\t" + intToWString(CoRe.size()) + L"\t"; // 아이디 입력 화면을 보냄 user, node, ch, sheet 순서
                            delete[] sheet34198;
                            std::cerr << "content = " << wstringToUtf8(content) << std::endl;
                            sendMsg(client_socket, content);
                        }
                        else if (clientMvec[1] == L"34,198" || clientMvec[1] == L"34198")
                        { // 아이디를 입력한 상태(비밀번호 입력 화면을 보내야 함)
                            // vector<uchar> IDList = CoRe[34196][1].first;
                            cerr << "clientMvec[1] = " << wstringToUtf8(clientMvec[1]) << endl;
                            uchar *IDList = axis1(34196, 1);
                            bool check = false;
                            uint startCoo = charTouint(CoRe[34196] + 6 + 4 * 1);
                            uint sizeIDList = charTouint(CoRe[34196] + startCoo);
                            wcout << L"sizeIDList = " << intToWString(sizeIDList) << endl;
                            for (int i = 0; i < sizeIDList / 6; i++)
                            {
                                if (clientMvec[3] == charToWstring(Sheet(*reinterpret_cast<uint *>(&IDList[6 * i])))) // ID가 존재하는 경우
                                {
                                    check = true;
                                    content = intToWString(i + 1) + L"\t" + intToWString(34199) + L"\t" + L"0" + L"\t" + charToWstring(Sheet(34199)) + L"\t" + intToWString(CoRe.size()) + L"\t"; // password 입력 화면을 보냄 user, node, sheet 순서
                                    sendMsg(client_socket, content);
                                    break;
                                }
                            }
                            if (!check)
                            {
                                content = intToWString(user) + L"\t" + intToWString(34198) + L"\t" + L"0" + L"\t" + L"없는 아이디입니다. 다시 아이디를 입력해 주세요."; // 다시 아이디 입력 화면을 보냄
                                sendMsg(client_socket, content);
                            }
                        }
                    }
                    else
                    { // 아이디까지 입력한 이후 상태
                        string inputText = wstringToUtf8(clientMvec[3]);
                        if (clientMvec[1] == L"34,199" || clientMvec[1] == L"34199")
                        { // 비밀번호 입력한 상태
                            uint startCoo = startCh(34196, 1);
                            pair<uint, ushort> userID = charToPair(CoRe[34196] + startCoo + 4 + 6 * (user - 1));
                            uint startUserID = startCh(userID.first, userID.second);
                            pair<uint, ushort> Pass = charToPair(CoRe[userID.first] + startUserID + 4);
                            if (clientMvec[3] == charToWstring(Sheet(Pass.first))) // 비밀번호가 동일한 경우
                            {
                                uint startPass = startCh(Pass.first, Pass.second);
                                pair<uint, ushort> start = charToPair(CoRe[Pass.first] + startPass + 4);
                                cNode[user] = start.first;
                                cCh[user] = start.second;
                                sendMsg(client_socket, makeContent(user, L""));
                            }
                            else
                            {
                                content = intToWString(user) + L"\t" + intToWString(34199) + L"\t" + L"0" + L"\t" + L"비밀번호가 틀립니다. 다시 입력해 주세요." + L"\t" + intToWString(CoRe.size()) + L"\t"; // password 입력 화면을 보냄 user, node, ch, sheet 순서
                                sendMsg(client_socket, content);
                            }
                        }
                        else
                        { // LogIn 이후 상태
                            int num = 0;
                            if (tryConvertToInt(inputText, num))
                            {
                                cerr << "num = " << wstringToUtf8(intToWString(num)) << endl;
                                if (num == 98)
                                {
                                    study(user);
                                    sendMsg(client_socket, makeContent(user, L"98"));
                                    cerr << "989898" << endl;
                                }
                                else if (num == 982) // if not working 98 function
                                {
                                    study2(user);
                                    content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + contentList(cNode[user], cCh[user]) + L"\t" + intToWString(CoRe.size()) + L"\t98";
                                    sendMsg(client_socket, content);
                                }
                                else if (num == 99)
                                {
                                    copyNode = make_pair(cNode[user], cCh[user]);
                                    sendMsg(client_socket, makeContent(user, L""));
                                }
                                else if (num == 100)
                                {
                                    if (copyNode.first != 0 && copyNode.second != 0)
                                    {
                                        link(cNode[user], cCh[user], copyNode.first, copyNode.second);
                                    }
                                    sendMsg(client_socket, makeContent(user, L""));
                                }
                                else if ((num > 0 && num <= sizeCoo(cNode[user], cCh[user]) / 6) || (num < 0 && -num <= sizeRev(cNode[user], cCh[user]) / 6))
                                {
                                    move(num, user);
                                    sendMsg(client_socket, makeContent(user, L""));
                                }
                            }
                            else
                            {
                                // std::cout << "Invalid argument: the wstring cannot be converted to an integer." << std::endl;
                                uint startCoo = charTouint(CoRe[6478] + 10);
                                uint sizeCoo = charTouint(CoRe[6478] + startCoo) / 6;
                                for (int i = 0; i < sizeCoo; i++)
                                { // 바로가기 기능 구현
                                    uint nextNode = charTouint(CoRe[6478] + startCoo + 4 + 6 * i);
                                    uchar *sheetNode = Sheet(nextNode);
                                    wstring ws = charToWstring(sheetNode);
                                    if (clientMvec[3] == ws)
                                    {
                                        ushort nextCh = charToushort(CoRe[6478] + startCoo + 8 + 6 * i);
                                        cNode[user] = nextNode;
                                        cCh[user] = nextCh;
                                        delete[] sheetNode;
                                        sendMsg(client_socket, makeContent(user, L"", L""));
                                        break;
                                    }
                                    else
                                    {
                                        delete[] sheetNode;
                                    }
                                }
                                if (clientMvec[3][0] == L'/')
                                {
                                    string str = wstringToUtf8(clientMvec[3].substr(1));
                                    AddStringToNode(str, cNode[user], cCh[user], user);
                                    sendMsg(client_socket, makeContent(user, L"", L""));
                                }
                                else if (inputText == "시작" || inputText == "start")
                                {
                                    cNode[user] = 0;
                                    cCh[user] = 1;
                                    sendMsg(client_socket, makeContent(user, L"", L""));
                                }
                                else if (inputText == "수정")
                                {
                                    uchar *sheetNode = Sheet(cNode[user]);
                                    sendMsg(client_socket, makeContent(user, L"@" + charToWstring(sheetNode), L""));
                                    delete[] sheetNode;
                                }
                                else if (clientMvec[3][0] == L'@')
                                {
                                    string str = inputText.substr(1);
                                    wstring wstr = utf8ToWstring(str);
                                    uchar *wstr2 = wstringToUChar(wstr);
                                    change_data(cNode[1], wstr2);
                                    delete[] wstr2;
                                    sendMsg(client_socket, makeContent(user, L""));
                                }
                                else if (clientMvec[3][0] == L'#') // Search
                                {
                                    string str = inputText.substr(1);
                                    wstring wstr = utf8ToWstring(str);
                                    uchar *wstr2 = wstringToUChar(wstr);
                                    uint dataSz = charTouint(wstr2);
                                    uint Node = firstToken(wstr2, dataSz);
                                    cNode[user] = Node;
                                    cCh[user] = 1;
                                    sendMsg(client_socket, makeContent(user, L""));
                                }
                                else if (inputText == "save" || inputText == "저장")
                                {
                                    save("");
                                    sendMsg(client_socket, makeContent(user, L"", L"save complete!"));
                                }
                                else if (inputText == "backUp")
                                {
                                    save("backup/");
                                    sendMsg(client_socket, makeContent(user, L"", L"backup complete!"));
                                }
                                else if (inputText == "del98")
                                { // 삭제하고 + 98
                                    deleteNode(cNode[user]);
                                    study(1);
                                    sendMsg(client_socket, makeContent(user, L"", L"del98 complete!"));
                                }
                                else if (inputText == "ch+")
                                { // channel plus
                                    ushort nc = numCh(cNode[user]);
                                    if (cCh[user] + 1 < nc)
                                    {
                                        cCh[user] += 1;
                                    }
                                    else
                                    {
                                        cCh[user] = 0;
                                    }
                                    sendMsg(client_socket, makeContent(user, L"", L""));
                                }
                                else if (inputText == "ch-")
                                { // 삭제하고 + 98
                                    ushort nc = numCh(cNode[user]);
                                    if (cCh[user] > 0)
                                    {
                                        cCh[user] -= 1;
                                    }
                                    else
                                    {
                                        cCh[user] = nc - 1;
                                    }
                                    sendMsg(client_socket, makeContent(user, L"", L""));
                                }
                                else if (inputText == "html")
                                { // edit index2.html file
                                    std::ifstream file("index2.html");
                                    if (!file.is_open())
                                    {
                                        std::cerr << "Failed to open file" << std::endl;
                                        continue; // Skip this iteration
                                    }
                                    std::string content_html((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                    content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + utf8ToWstring(content_html) + L"\t" + intToWString(CoRe.size()) + L"\thtml";
                                    sendMsg(client_socket, content);
                                }
                                else if (inputText == "editHtml")
                                {
                                    std::ofstream file("index2.html");
                                    if (file.is_open())
                                    {
                                        // 요청 본문에서 "content" 필드의 값을 파일에 쓴다고 가정
                                        file << wstringToUtf8(clientMvec[4]);
                                        file.close();
                                        std::cout << "File updated successfully.\n";
                                    }
                                    else
                                    {
                                        std::cout << "Error opening file.\n";
                                    }
                                }
                                else if (inputText == "cpp")
                                { // edit index2.html file
                                    std::ifstream file("new20.cpp");
                                    if (!file.is_open())
                                    {
                                        std::cerr << "Failed to open file" << std::endl;
                                        continue; // Skip this iteration
                                    }
                                    std::string content_html((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                    content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + utf8ToWstring(content_html) + L"\t" + intToWString(CoRe.size()) + L"\tcpp";
                                    sendMsg(client_socket, content);
                                }
                                else if (inputText == "editcpp")
                                {
                                    std::ofstream file("new20.cpp");
                                    if (file.is_open())
                                    {
                                        // 요청 본문에서 "content" 필드의 값을 파일에 쓴다고 가정
                                        file << wstringToUtf8(clientMvec[4]);
                                        file.close();
                                        std::cout << "File updated successfully.\n";
                                    }
                                    else
                                    {
                                        std::cout << "Error opening file.\n";
                                    }
                                }
                                else if (inputText.size() >= 4 && inputText.substr(0, 4) == "103,")
                                { // 연결 해제
                                    vector<string> spl = splitStringASCII(inputText, ',');
                                    if (spl.size() == 2)
                                    {
                                        int tt = stringToUint(spl[1]) - 1;
                                        cut(cNode[1], cCh[1], tt);
                                        content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + contentList(cNode[user], cCh[user]) + L"\t" + intToWString(CoRe.size()) + L"\t";
                                        sendMsg(client_socket, content);
                                    }
                                    else
                                    {
                                        Log(L"올바른 입력 형식이 아닙니다. ");
                                    }
                                    // display(cNode[1], cCh[1]);
                                    inputText.clear();
                                }
                                else if (inputText.size() >= 4 && inputText.substr(0, 4) == "104,")
                                { // 자식 node로 이동
                                    cerr << "call 104, function" << endl;
                                    vector<string> spl = splitStringASCII(inputText, ',');
                                    if (spl.size() == 3)
                                    {
                                        uint startCoo = startCh(cNode[1], cCh[1]);
                                        uint res2 = charTouint(CoRe[cNode[1]] + startCoo + 4 + 6 * (stringToUint(spl[1]) - 1));
                                        int tt = 6 * (stringToUint(spl[2]) - 1);
                                        CoMove(cNode[1], cCh[1], res2, charTouint(CoRe[cNode[1]] + startCoo + 4 + tt), charToushort(CoRe[cNode[1]] + startCoo + 8 + tt));
                                        content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + contentList(cNode[user], cCh[user]) + L"\t" + intToWString(CoRe.size()) + L"\t";
                                        sendMsg(client_socket, content);
                                    }
                                    else
                                    {
                                        Log(L"올바른 입력 형식이 아닙니다. ");
                                    }
                                    // clearInputText();
                                }
                                else if (inputText.size() >= 4 && inputText.substr(0, 4) == "del,")
                                {
                                    vector<string> spl = splitStringASCII(inputText, ',');
                                    if (spl.size() == 2)
                                    {
                                        uint startCoo = startCh(cNode[1], cCh[1]);
                                        int tt = stringToUint(spl[1]) - 1;
                                        uint deln = charTouint(CoRe[cNode[1]] + startCoo + 4 + 6 * tt);
                                        cut(cNode[1], cCh[1], tt);
                                        deleteNode(deln);
                                        Log(intToWString(deln) + L" 삭제!");
                                    }
                                    else
                                    {
                                        Log(L"올바른 입력 형식이 아닙니다. ");
                                    }
                                    // info();
                                    sendMsg(client_socket, makeContent(user, L"", L""));
                                    // clearInputText();
                                }
                                else if (inputText.size() >= 5 && inputText.substr(0, 5) == "move,")
                                {
                                    cerr << "call move function" << endl;
                                    vector<string> spl = splitStringASCII(inputText, ',');
                                    if (spl.size() == 3)
                                    {
                                        uint node = stringToUint(spl[1]);
                                        ushort ch = stringToUint(spl[2]);
                                        cNode[1] = node;
                                        cCh[1] = ch;
                                        content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + contentList(cNode[user], cCh[user]) + L"\t" + intToWString(CoRe.size()) + L"\t";
                                        sendMsg(client_socket, content);
                                    }
                                    else
                                    {
                                        Log(L"올바른 입력 형식이 아닙니다. ");
                                    }
                                    // clearInputText();
                                }
                                else if (inputText.size() >= 4 && inputText.substr(0, 4) == "page")
                                {
                                    vector<string> spl = splitStringASCII(inputText, 'e');
                                    if (spl.size() == 2)
                                    {
                                        uint page = stringToUint(spl[1]);
                                        content = intToWString(user) + L"\t" + intToWString(cNode[user]) + L"\t" + intToWString(cCh[user]) + L"\t" + contentList(cNode[user], cCh[user], page) + L"\t" + intToWString(CoRe.size()) + L"\t";
                                        sendMsg(client_socket, content);
                                    }
                                    else
                                    {
                                        sendMsg(client_socket, makeContent(user, L"", L"올바른 입력 형식이 아닙니다."));
                                    }
                                }
                                else if (inputText.size() >= 4 && inputText.substr(0, 4) == "map/")
                                {
                                    vector<string> spl = splitStringASCII(inputText, '/');
                                    if (spl.size() == 3)
                                    {
                                        AddStringToNode2(spl[1], spl[2], cNode[user], cCh[user], user);
                                        sendMsg(client_socket, makeContent(user, L"", L""));
                                    }
                                    else
                                    {
                                        sendMsg(client_socket, makeContent(user, L"", L"올바른 입력 형식이 아닙니다."));
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    std::cerr << "POST request without content" << std::endl;
                }
            }
        }
        close(client_socket);
    }
    close(serverSocket);
}
int main(int argc, char const *argv[])
{
    auto start = std::chrono::high_resolution_clock::now();
    std::locale::global(std::locale("en_US.UTF-8"));
    // std::wcout.imbue(std::locale());
    //  RAM에 Brain UpRoad
    std::ifstream in("Brain3-test.bin", std::ios::binary);
    // int ii = 0;
    uchar *size2 = new uchar[4];
    in.read(reinterpret_cast<char *>(size2), sizeof(uint));
    uint size3 = charTouint(size2);
    wstring ww = intToWString(size3);
    // std::cerr << "Node: " << wstringToUtf8(ww) << std::endl;
    // Log(L"Node" + ww);
    for (int i = 0; i < size3; i++)
    {
        uchar *size1 = new uchar[4];
        in.read(reinterpret_cast<char *>(size1), sizeof(uint));
        uint size = charTouint(size1);
        uchar *outer = new uchar[size + 4];
        outer[0] = size1[0];
        outer[1] = size1[1];
        outer[2] = size1[2];
        outer[3] = size1[3];
        delete[] size1;
        in.read(reinterpret_cast<char *>(&outer[4]), size);
        CoRe.push_back(outer);
    }
    in.close();

    string file_path2 = "order3-test.bin";
    read_order(file_path2);
    cNode[1] = 0;
    cCh[1] = 1;

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    Log(L"loading time: " + intToWString(duration.count()) + L"ms");
    getMemoryUsage(vmSize, vmRSS);

    thread t1(Network);
    thread t2(Network2);
    t1.join();
    t2.join();
    return 0;
}
