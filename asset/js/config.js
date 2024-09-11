// 환경별 설정
const configs = {
    development: {
      apiUrl: 'https://improved-zebra-wpw5q79q7wg3559r-35500.app.github.dev/',
      wsUrl: 'wss://dev-ws.example.com'
    },
    staging: {
      apiUrl: 'https://staging-api.example.com',
      wsUrl: 'wss://staging-ws.example.com'
    },
    production: {
      apiUrl: 'https://alsteam23.kro.kr:35500/',
      wsUrl: 'wss://ws.example.com'
    }
  };
  
  // 현재 환경 설정 (환경 변수 또는 빌드 설정에 따라 결정)
  const currentEnv = process.env.NODE_ENV || 'development';
  
  // 현재 환경에 해당하는 설정 내보내기
  export default configs[currentEnv];
  