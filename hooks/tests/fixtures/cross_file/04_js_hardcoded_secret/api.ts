// Primary file: uses imported config for API authentication
import { getApiKey } from './config';

export async function fetchData(endpoint: string) {
    const response = await fetch(endpoint, {
        headers: { 'Authorization': `Bearer ${getApiKey()}` }
    });
    return response.json();
}
